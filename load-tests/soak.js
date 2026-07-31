import http from "k6/http";
import { check } from "k6";

export const options = {
    vus: 50,
    duration: "15m",

    threshold: {
        http_req_failed: ["rate<0.01"],
        http_req_duration: ["p(95)<500"],
    },
};

export default function () {
    const res = http.post(
        "http://127.0.0.1:8100/v1/analyze",
        JSON.stringify({
            prompt: "Explain machine learning",
        }),
        {
            headers: {
                "Content-Type": "application/json",
                "x-api-key": "tenet-dev-key-change-in-production",
            },
        }
    );
    check(res, {
        "status is 200 or 429": (r) =>
            r.status === 200 || r.status === 429,
    });
}