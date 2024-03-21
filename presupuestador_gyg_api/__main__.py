from dotenv import load_dotenv

from presupuestador_gyg_api import create_app

if __name__ == "__main__":
    load_dotenv("../.env")
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
