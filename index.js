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
			if(err) cb(err)
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
        req.client = getClient(req.user && req.user.iss)
        next()
    }
    app.use(putClient)

    app.post('/subscription', (req, res) => {
        if(!req.client) return res.status(401).send('client not found')
        const issuer = req.client.issuer
        const identifier = req.user[req.client.identifier]
        if(!identifier) return res.status(400).send('identifier not found')
        const subscription = req.body

        mongodbClient.connect()
            .then(client => {
                client.db().collection('subscriptions').updateOne(
                    { issuer, identifier, subscription },
                    { $set: { issuer, identifier, subscription }},
                    { upsert: true },
                )
                .then(() => res.status(201).send())
                .catch(err => res.status(500).send(err))
            })
            .catch(err => res.status(500).send('can\'t connect to db' + err))
    })

    app.post('/push', (req, res) => {
        if(!req.client) return res.status(401).send('client not found')
        const issuer = req.client.issuer
        if(!req.user.mayPush) return res.status(403).send('missing claim')

        const recipient = req.body.recipient
        if(!recipient) return res.status(400).send('field recipient required')
        const payload = req.body.payload
        if(!payload) return res.status(400).send('field payload required')

        const query = { issuer }
        if(recipient !== 'all') query.identifier = recipient
        mongodbClient.connect()
        .then(client => {
            client.db().collection('subscriptions').find( query ).toArray()
                .then(subscriptions => {
                    if(subscriptions.length === 0) return res.status(404).send('recipient not found')

                    subscriptions.map(({ subscription }) => webpush.sendNotification(subscription, 'Your Push Payload Text'))
                    res.status(200).send()
                })
                .catch(err => res.status(500).send(err))
        })
        .catch(err => res.status(500).send('can\'t connect to db' + err))
    })

    app.get('/vapid', (req, res) => {
        res.send({publicKey: config.webPush.publicKey})
    })

    app.listen(config.express.port, () => console.log(`Server listening on port ${config.express.port}!`))
})
.catch(console.log)