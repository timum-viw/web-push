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

async.parallel(
    config.clients.map(client => 
        cb => request(client.pub_key_url, (err, res, body) => {
			if(err) cb(null, {})
			else cb(null, {...client, key: body})
		})
    )
)
.then(clients => {
    const getClient = issuer => clients.find(c => c.issuer === issuer)

    const secret = (req, payload, done) => done(null, getClient(payload.iss) ? getClient(payload.iss).key : null)
    app.use(jwt({ algorithms: ['RS256'], secret, audience: config.jwt.audience }).unless({ path: [ '/vapid' ] }))

    app.use(bodyParser.json())
    app.use(cors({ origin: config.express.cors_origin, allowedHeaders: [ 'Authorization', 'Content-Type' ] }))

    function putClient(req, res, next) {
        const client = getClient(req.user && req.user.iss)
        if(!client) return res.status(401).send('client not found')
        req.client = client
        next()
    }
    app.use(putClient)

    app.post('/subscription', (req, res) => {
        const issuer = req.client.issuer
        const identifier = req.user.web_push_id
        if(!identifier) return res.status(400).send('identifier not found')
        const subscription = req.body

        mongodbClient.connect()
        .then(client => {
            client.db().collection(issuer).updateOne(
                { ...subscription, identifier },
                { $set: { ...subscription, identifier }},
                { upsert: true },
                )
                .then(() => res.status(201).send())
                .catch(err => res.status(500).send(err))
            })
            .catch(err => res.status(500).send('can\'t connect to db' + err))
    })
    
    const getSubscriptions = (issuer, query = {} ) => mongodbClient.connect().then(client => client.db().collection(issuer).find( query ).toArray())
    
    const push = (subscription, payload) => webpush.sendNotification(subscription, JSON.stringify(payload))
    
    app.use(['/broadcast', '/push'], (req, res, next) => {
        if(!req.user.mayPush) return res.status(403).send('missing claim')
        if(!req.body.payload) return res.status(400).send('field payload required')
        next()
    })
    
    app.post('/broadcast', (req, res) => {
        const payload = req.body.payload
        const issuer = req.client.issuer
        getSubscriptions(issuer)
        .then(subscriptions => {
            subscriptions.map(subscription => push(subscription, payload))
            res.status(200).send()
        })
        .catch(err => res.status(500).send(err))
    })
    
    app.post('/push', (req, res) => {
        let recipients = (req.body.recipients || [])
        if(!Array.isArray(recipients)) return res.status(400).send('recipients needs to be an array of identifiers')
        recipients = recipients.concat(req.body.recipient || [])
        if(recipients.length === 0) return res.status(400).send('field recipients or recipient required')
        
        const payload = req.body.payload
        const query = { identifier: { $in: recipients }}
        getSubscriptions(issuer, query)
        .then(subscriptions => {
            if(req.body.recipient && subscriptions.length === 0) return res.status(404).send('recipient not found')
            subscriptions.map(({ subscription }) => push(subscription, payload))
            res.status(200).send()
        })
        .catch(err => res.status(500).send(err))
    })

    app.get('/vapid', (req, res) => {
        res.send({publicKey: config.webPush.publicKey})
    })

    app.listen(config.express.port, () => console.log(`Server listening on port ${config.express.port}!`))
})
.catch(console.log)