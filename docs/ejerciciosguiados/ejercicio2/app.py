from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

# URL de Ollama (ya levantado en el host)
OLLAMA_API_URL = "http://localhost:11434/api/chat"

@app.route("/api/chat")
def index():
    return render_template("index.html")

@app.route("/ask", methods=["POST"])
def ask():
    user_message = request.json.get("message")
    payload = {
        "model": "deepseek-coder",
        "messages": [{"role": "user", "content": user_message}],
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_API_URL, json=payload)
        response.raise_for_status()
        data = response.json()
        # Devuelve el contenido de la respuesta
        return jsonify({"reply": data["message"]["content"]})
    except Exception as e:
        return jsonify({"reply": f"Error: {str(e)}"})

if __name__ == "__main__":
    # Flask corre en localhost:5000
    app.run(debug=True, host="0.0.0.0", port=5000)
