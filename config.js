const port = 4321

const config = {
    clients: [
        {
            pub_key_url: process.env.JWT_PUB_KEY_URL || 'http://llp/zend/mobil/publickey',
            issuer: process.env.JWT_ISSUER || `http://llp`,
            identifier: 'student_id',
        }
    ],
    webPush: {
        subject: process.env.VAPID_SUBJECT || `http://localhost:${port}`,
        publicKey: process.env.VAPID_PUBLIC_KEY,
        privateKey: process.env.VAPID_PRIVATE_KEY
    },
	jwt: {
		audience: process.env.JWT_AUDIENCE || `http://localhost:${port}`,
	},
	express: {
		port: process.env.PORT || port,
		cors_origin: process.env.CORS_ORIGIN || 'http://localhost:9000'
	},
	mongodb: {
		uri: process.env.MONGODB_URI || 'mongodb://user:pass@localhost:27017/web-push'
	}
}

module.exports = config