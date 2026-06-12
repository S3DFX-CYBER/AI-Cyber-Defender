from locust import HttpUser, task, between

API_KEY = "test-api-key"


class TENETLoadUser(HttpUser):
    wait_time = between(1, 3)

    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json",
    }

    @task(3)
    def health_check(self):
        self.client.get(
            "/health",
            headers=self.headers,
            name="GET /health"
        )

    @task(2)
    def get_stats(self):
        self.client.get(
            "/v1/stats",
            headers=self.headers,
            name="GET /v1/stats"
        )

    @task(2)
    def list_events(self):
        self.client.get(
            "/v1/events",
            headers=self.headers,
            name="GET /v1/events"
        )

    @task(1)
    def submit_llm_event(self):
        payload = {
            "source_type": "chat",
            "source_id": "load-test-user",
            "model": "gpt-4",
            "prompt": "This is a load testing request",
            "system_prompt": "You are a helpful assistant",
            "metadata": {
                "environment": "load-test"
            }
        }

        self.client.post(
            "/v1/events/llm",
            json=payload,
            headers=self.headers,
            name="POST /v1/events/llm"
        )