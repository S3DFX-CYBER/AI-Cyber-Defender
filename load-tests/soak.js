import http from "k6/http";

export const options = {
    vus: 50,
    duration: "15m",
};

export default function () {
    http.post(
        "http://127.0.0.1:8101/v1/analyze",
        JSON.stringify({
            prompt: "Explain machine learning"
        }),
        {
            headers: {
                "Content-Type": "application/json",
                "x-api-key": "tenet-dev-key-change-in-production"
            }
        }
    );
}