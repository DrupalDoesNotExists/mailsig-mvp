import datetime
from os import getenv

from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

import crypto
import lookup


def load_keypair() -> crypto.KeyPair:
    return crypto.load_pem_keys(
        getenv(f"MSIG_PRIVKEY"),
        getenv(f"MSIG_PUBKEY")
    )


keypair = load_keypair()
signature_ttl = datetime.timedelta(
    hours=int(getenv("MSIG_TTL_HOURS"))
)

app = Flask(__name__)
api = Api(app)


class ValidationResource(Resource):
    
    def get(self):
        """
        Validates the domain
        ---
        parameters:
            - in: query
              name: domain
              type: string
              required: true
        responses:
            200:
                description: Validation result
                schema:
                    id: Validation
                    properties:
                        valid:
                            type: boolean
                            description: Is domain valid
                            default: false
                        signatures:
                            type: array
                            items:
                                type: string
                            description: List of available mailsig signatures
                        outdated:
                            type: boolean
                            description: Is the outdated iteration signature matched
                            default: false
        """
        domain = request.args["domain"]
        signatures = lookup.query_records(domain)
        
        valid = False
        outdated = False
        if signatures:
            actsig, prevsig = signatures
            if crypto.check_signature(keypair.pubkey, domain, actsig):
                valid = True
            if prevsig and crypto.check_signature(keypair.pubkey, domain, prevsig):
                valid = outdated = True
        
        return {"valid": valid, "signatures": signatures, "outdated": outdated}


class SignResource(Resource):
    
    def get(self):
        """
        Creates a signature
        ---
        parameters:
            - in: query
              name: domain
              type: string
              required: true
        responses:
            200:
                description: Signature contents
                schema:
                    id: Signature
                    properties:
                        signature:
                            type: string
                            description: JWT MailSig signature
        """
        domain = request.args["domain"]
        signature = crypto.create_signature(keypair.privkey, domain, signature_ttl)
        return {"signature": signature}


api.add_resource(ValidationResource, "/validation")
api.add_resource(SignResource, "/sign")


swag = swagger(app)
swag['info']['version'] = "1.0"
swag['info']['title'] = "MailSig"


@app.route("/swagger")
def get_swagger():
    return jsonify(swag)


SWAGGER_URL = ''
API_URL = '/swagger'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "MailSig"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
