require('dotenv').config()
const config = require('./config')

const MongoClient = require('mongodb').MongoClient
const mongodbClient = new MongoClient(config.mongodb.uri, { useNewUrlParser: true })

const webpush = require('web-push')
webpush.setVapidDetails(
    config.webPush.subject,
    config.webPush.publicKey,
    config.webPush.privateKey
)

const jwt = require('express-jwt')
const express = require('express')
const app = express()
const bodyParser = require('body-parser')
const cors = require('cors')
const async = require('async')
const request = require('request')

async.parallel([
    cb => mongodbClient.connect().then( client => cb(null, client.db())),
    ...config.clients.map(client => 
        cb => request(client.pub_key_url, (err, res, body) => {
            if(err) cb(null, {})
            else cb(null, {...client, key: body})
        })
    )
])
.then(([mongodb, ...clients]) => {
    const getClient = issuer => clients.find(c => c.issuer === issuer)

    const secret = (req, payload, done) => done(null, getClient(payload.iss) ? getClient(payload.iss).key : null)
    app.use(jwt({ algorithms: ['RS256'], secret, audience: config.jwt.audience }).unless({ path: [ '/vapid' ] }))

    app.use(bodyParser.json())
    app.use(cors({ origin: config.express.cors_origin, allowedHeaders: [ 'Authorization', 'Content-Type' ] }))

    function putClient(req, res, next) {
        const client = getClient(req.user && req.user.iss)
        if(!client) return res.status(401).send({error: 'client not found'})
        req.client = client
        next()
    }
    app.use(putClient)

    app.post('/subscription', (req, res) => {
        const issuer = req.client.issuer
        const identifier = req.user.web_push_id
        if(!identifier) return res.status(400).send({error: 'identifier not found'})
        const subscription = req.body

        mongodb.collection(issuer.replace('http://', '')).updateOne(
            { ...subscription, identifier },
            { $set: { ...subscription, identifier }},
            { upsert: true },
            )
            .then(() => res.status(201).send())
            .catch(error => res.status(500).send({error}))
    })
    
    const getSubscriptions = (issuer, query = {} ) => mongodb.collection(issuer.replace('http://', '')).find( query ).toArray()
    
    const removeStaleSubscription = (issuer, subscription) => err => {
        if([404, 410].indexOf(err.statusCode) < 0) return
        mongodb.collection(issuer.replace('http://', '')).deleteOne( subscription )
    }

    const push = (issuer, subscription, payload) => webpush.sendNotification(subscription, JSON.stringify(payload)).catch(removeStaleSubscription(issuer, subscription))
    
    app.use(['/broadcast', '/push'], (req, res, next) => {
        if(!req.user.mayPush) return res.status(403).send({error: 'missing claim'})
        if(!req.body.payload) return res.status(400).send({error: 'field payload required'})
        next()
    })
    
    app.post('/broadcast', (req, res) => {
        const payload = req.body.payload
        const issuer = req.client.issuer
        getSubscriptions(issuer)
        .then(subscriptions => {
            subscriptions.map(subscription => push(issuer, subscription, payload))
            res.status(200).send()
        })
        .catch(error => res.status(500).send({error}))
    })
    
    app.post('/push', (req, res) => {
        let recipients = (req.body.recipients || [])
        if(!Array.isArray(recipients)) return res.status(400).send({error: 'recipients needs to be an array of identifiers'})
        recipients = recipients.concat(req.body.recipient || [])
        if(recipients.length === 0) return res.status(400).send({error: 'field recipients or recipient required'})
        
        const issuer = req.client.issuer
        const payload = req.body.payload
        const query = { identifier: { $in: recipients }}
        getSubscriptions(issuer, query)
        .then(subscriptions => {
            if(req.body.recipient && subscriptions.length === 0) return res.status(404).send({error: 'recipient not found'})
            subscriptions.map(subscription => push(issuer, subscription, payload))
            res.status(200).send()
        })
        .catch(error => res.status(500).send({error}))
    })

    app.get('/vapid', (req, res) => {
        res.send({publicKey: config.webPush.publicKey})
    })

    app.listen(config.express.port, () => console.log(`Server listening on port ${config.express.port}!`))
})
.catch(console.log)