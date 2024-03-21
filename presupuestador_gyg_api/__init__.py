from flask import Flask, request


def create_app():
    new_app = Flask(__name__)

    @new_app.route("/")
    def home_page():
        request_query = request.args
        if request_query:

            response = ["Counter Server Working (Not that counter...)", "<ul>"]

            for arg, value in request_query.items():
                response.append(f"<li>{arg}: {value}</li>")

            response.append("</ul>")

            response = "".join(response)

            return response

        return "Counter Server Working (Not that counter...)"

    from presupuestador_gyg_api.api import complete_api_bp

    new_app.register_blueprint(complete_api_bp)

    return new_app
