&#x20;TENET AI Production Deployment \& Operations Runbook



\## Table of Contents

1\. \[VPS Bare-Metal Deployment](#vps-bare-metal-deployment)

2\. \[Docker Deployment](#docker-deployment)

3\. \[Reverse Proxy \& SSL Configuration](#reverse-proxy--ssl-configuration)

4\. \[Scaling Guide](#scaling-guide)

5\. \[Backup Strategy](#backup-strategy)

6\. \[Incident Response](#incident-response)



\---



\## VPS Bare-Metal Deployment



\### Prerequisites

\- Ubuntu 22.04/24.04 LTS (recommended)

\- Python 3.11+

\- PostgreSQL 15+

\- Redis 7+

\- MinIO (or any S3-compatible storage)

\- 4GB RAM minimum (8GB recommended)



\### Step-by-Step Deployment



\#### 1. System Update \& Essential Packages

```bash

sudo apt update \&\& sudo apt upgrade -y

sudo apt install -y python3-pip python3-venv nginx postgresql redis-server git

2\. Clone Repository

bash

git clone https://github.com/TENET-DEV-AI/TENET-AI.git /opt/tenet-ai

cd /opt/tenet-ai

3\. Setup Python Environment

bash

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt

4\. Configure PostgreSQL

bash

sudo -u postgres psql

sql

CREATE DATABASE tenet\_db;

CREATE USER tenet\_user WITH PASSWORD 'strong\_password';

GRANT ALL PRIVILEGES ON DATABASE tenet\_db TO tenet\_user;

\\q

5\. Configure Redis

bash

sudo systemctl enable redis-server

sudo systemctl start redis-server

6\. Environment Configuration

bash

cp .env.template .env

\# Edit .env with:

\# DATABASE\_URL=postgresql://tenet\_user:strong\_password@localhost/tenet\_db

\# REDIS\_URL=redis://localhost:6379/0

\# OPENAI\_API\_KEY=your\_key

7\. Train Detection Model

bash

python scripts/train\_model.py

8\. Create Systemd Services

Create /etc/systemd/system/tenet-ingest.service:



ini

\[Unit]

Description=TENET AI Ingest Service

After=network.target postgresql.service redis-server.service



\[Service]

Type=simple

User=www-data

WorkingDirectory=/opt/tenet-ai

Environment="PATH=/opt/tenet-ai/venv/bin"

ExecStart=/opt/tenet-ai/venv/bin/python services/ingest/app.py

Restart=always

RestartSec=10



\[Install]

WantedBy=multi-user.target

Create /etc/systemd/system/tenet-analyzer.service (similar, using services/analyzer/app.py).



9\. Start Services

bash

sudo systemctl daemon-reload

sudo systemctl enable tenet-ingest tenet-analyzer

sudo systemctl start tenet-ingest tenet-analyzer

sudo systemctl status tenet-ingest

Docker Deployment

Prerequisites

Docker Engine 24+



Docker Compose v2+



2GB minimum RAM per service



Deployment Steps

1\. Prepare Directory Structure

bash

mkdir -p tenet-deployment/{data,logs,backups}

cd tenet-deployment

2\. Create docker-compose.yml

yaml

version: '3.8'



services:

&#x20; postgres:

&#x20;   image: postgres:15-alpine

&#x20;   environment:

&#x20;     POSTGRES\_DB: tenet\_db

&#x20;     POSTGRES\_USER: tenet\_user

&#x20;     POSTGRES\_PASSWORD: ${DB\_PASSWORD}

&#x20;   volumes:

&#x20;     - ./data/postgres:/var/lib/postgresql/data

&#x20;   networks:

&#x20;     - tenet-network

&#x20;   healthcheck:

&#x20;     test: \["CMD-SHELL", "pg\_isready -U tenet\_user"]

&#x20;     interval: 10s

&#x20;     timeout: 5s

&#x20;     retries: 5



&#x20; redis:

&#x20;   image: redis:7-alpine

&#x20;   command: redis-server --appendonly yes

&#x20;   volumes:

&#x20;     - ./data/redis:/data

&#x20;   networks:

&#x20;     - tenet-network

&#x20;   healthcheck:

&#x20;     test: \["CMD", "redis-cli", "ping"]

&#x20;     interval: 10s

&#x20;     timeout: 5s

&#x20;     retries: 5



&#x20; minio:

&#x20;   image: minio/minio:latest

&#x20;   command: server /data --console-address ":9001"

&#x20;   environment:

&#x20;     MINIO\_ROOT\_USER: ${MINIO\_ACCESS\_KEY}

&#x20;     MINIO\_ROOT\_PASSWORD: ${MINIO\_SECRET\_KEY}

&#x20;   volumes:

&#x20;     - ./data/minio:/data

&#x20;   ports:

&#x20;     - "9000:9000"

&#x20;     - "9001:9001"

&#x20;   networks:

&#x20;     - tenet-network



&#x20; ingest:

&#x20;   build:

&#x20;     context: .

&#x20;     dockerfile: Dockerfile

&#x20;   environment:

&#x20;     DATABASE\_URL: postgresql://tenet\_user:${DB\_PASSWORD}@postgres/tenet\_db

&#x20;     REDIS\_URL: redis://redis:6379/0

&#x20;     MINIO\_ENDPOINT: minio:9000

&#x20;   depends\_on:

&#x20;     postgres:

&#x20;       condition: service\_healthy

&#x20;     redis:

&#x20;       condition: service\_healthy

&#x20;   ports:

&#x20;     - "8000:8000"

&#x20;   networks:

&#x20;     - tenet-network

&#x20;   deploy:

&#x20;     resources:

&#x20;       limits:

&#x20;         cpus: '1'

&#x20;         memory: 1G

&#x20;   restart: unless-stopped



&#x20; analyzer:

&#x20;   build:

&#x20;     context: .

&#x20;     dockerfile: Dockerfile.analyzer

&#x20;   environment:

&#x20;     REDIS\_URL: redis://redis:6379/0

&#x20;   depends\_on:

&#x20;     redis:

&#x20;       condition: service\_healthy

&#x20;   networks:

&#x20;     - tenet-network

&#x20;   deploy:

&#x20;     resources:

&#x20;       limits:

&#x20;         cpus: '2'

&#x20;         memory: 2G

&#x20;   restart: unless-stopped



&#x20; dashboard:

&#x20;   build:

&#x20;     context: ./dashboard

&#x20;     dockerfile: Dockerfile

&#x20;   ports:

&#x20;     - "3000:3000"

&#x20;   networks:

&#x20;     - tenet-network

&#x20;   restart: unless-stopped



networks:

&#x20; tenet-network:

&#x20;   driver: bridge

3\. Create .env file

env

DB\_PASSWORD=your\_strong\_password\_here

MINIO\_ACCESS\_KEY=minioadmin

MINIO\_SECRET\_KEY=minioadmin123

4\. Create Dockerfiles

Dockerfile (for ingest service):



dockerfile

FROM python:3.11-slim



WORKDIR /app



COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt



COPY services/ingest ./services/ingest

COPY tenet\_plugin ./tenet\_plugin



EXPOSE 8000



CMD \["python", "services/ingest/app.py"]

Dockerfile.analyzer (for analyzer service):



dockerfile

FROM python:3.11-slim



WORKDIR /app



COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt



COPY services/analyzer ./services/analyzer

COPY models ./models



CMD \["python", "services/analyzer/app.py"]

5\. Deploy

bash

docker-compose up -d

docker-compose ps

docker-compose logs -f

6\. Update Deployment

bash

git pull origin main

docker-compose down

docker-compose build --no-cache

docker-compose up -d

Reverse Proxy \& SSL Configuration

Nginx Configuration

Create /etc/nginx/sites-available/tenet-ai:



nginx

server {

&#x20;   listen 80;

&#x20;   server\_name tenet.yourdomain.com;

&#x20;   return 301 https://$server\_name$request\_uri;

}



server {

&#x20;   listen 443 ssl http2;

&#x20;   server\_name tenet.yourdomain.com;



&#x20;   ssl\_certificate /etc/letsencrypt/live/tenet.yourdomain.com/fullchain.pem;

&#x20;   ssl\_certificate\_key /etc/letsencrypt/live/tenet.yourdomain.com/privkey.pem;

&#x20;   

&#x20;   ssl\_protocols TLSv1.2 TLSv1.3;

&#x20;   ssl\_ciphers HIGH:!aNULL:!MD5;

&#x20;   ssl\_prefer\_server\_ciphers on;



&#x20;   # Ingest API

&#x20;   location /api/ {

&#x20;       proxy\_pass http://localhost:8000/;

&#x20;       proxy\_set\_header Host $host;

&#x20;       proxy\_set\_header X-Real-IP $remote\_addr;

&#x20;       proxy\_set\_header X-Forwarded-For $proxy\_add\_x\_forwarded\_for;

&#x20;       proxy\_set\_header X-Forwarded-Proto $scheme;

&#x20;   }



&#x20;   # Dashboard

&#x20;   location / {

&#x20;       proxy\_pass http://localhost:3000;

&#x20;       proxy\_set\_header Host $host;

&#x20;       proxy\_set\_header X-Real-IP $remote\_addr;

&#x20;   }

}

SSL with Let's Encrypt

bash

\# Install Certbot

sudo apt install certbot python3-certbot-nginx -y



\# Obtain certificate

sudo certbot --nginx -d tenet.yourdomain.com



\# Auto-renewal (certbot renew --dry-run)

Caddy (Alternative - Simpler)

Create Caddyfile:



text

tenet.yourdomain.com {

&#x20;   reverse\_proxy /api/\* localhost:8000

&#x20;   reverse\_proxy /\* localhost:3000

&#x20;   tls admin@yourdomain.com

}

Run: caddy run --config Caddyfile



Scaling Guide

Vertical Scaling

Increase resources on existing VPS:



CPU: 4-8 cores



RAM: 8-16GB



Storage: 50-100GB SSD



Update Docker resources in docker-compose.yml:



yaml

deploy:

&#x20; resources:

&#x20;   limits:

&#x20;     cpus: '4'

&#x20;     memory: 8G

Horizontal Scaling (Multi-Node)

1\. Load Balancer Setup (HAProxy)

bash

sudo apt install haproxy

Configure /etc/haproxy/haproxy.cfg:



haproxy

frontend tenet\_frontend

&#x20;   bind \*:80

&#x20;   bind \*:443 ssl crt /etc/ssl/certs/tenet.pem

&#x20;   default\_backend tenet\_servers



backend tenet\_servers

&#x20;   balance roundrobin

&#x20;   server node1 10.0.0.1:8000 check

&#x20;   server node2 10.0.0.2:8000 check

&#x20;   server node3 10.0.0.3:8000 check

2\. Redis Sentinel for HA

yaml

\# docker-compose.yml addition

redis-sentinel:

&#x20; image: redis:7-alpine

&#x20; command: redis-sentinel /usr/local/etc/redis/sentinel.conf

&#x20; volumes:

&#x20;   - ./sentinel.conf:/usr/local/etc/redis/sentinel.conf

3\. Database Replication (PostgreSQL)

bash

\# On primary

sudo -u postgres psql -c "ALTER SYSTEM SET wal\_level = replica;"

sudo systemctl restart postgresql



\# On replica

sudo -u postgres pg\_basebackup -h primary\_ip -D /var/lib/postgresql/15/main -U replication\_user -P --wal-method=stream

Auto-scaling (Kubernetes)

For advanced auto-scaling, deploy to Kubernetes with HPA:



yaml

apiVersion: autoscaling/v2

kind: HorizontalPodAutoscaler

metadata:

&#x20; name: tenet-ingest-hpa

spec:

&#x20; scaleTargetRef:

&#x20;   apiVersion: apps/v1

&#x20;   kind: Deployment

&#x20;   name: tenet-ingest

&#x20; minReplicas: 2

&#x20; maxReplicas: 10

&#x20; metrics:

&#x20; - type: Resource

&#x20;   resource:

&#x20;     name: cpu

&#x20;     target:

&#x20;       type: Utilization

&#x20;       averageUtilization: 70

Backup Strategy

Automated Backup Script

Create /opt/tenet-ai/scripts/backup.sh:



bash

\#!/bin/bash

BACKUP\_DIR="/backups/tenet-ai"

DATE=$(date +%Y%m%d\_%H%M%S)

RETENTION\_DAYS=30



\# Create backup directory

mkdir -p $BACKUP\_DIR/{db,redis,minio,config}



\# Backup PostgreSQL

PGPASSWORD=$DB\_PASSWORD pg\_dump -U tenet\_user -h localhost tenet\_db | gzip > $BACKUP\_DIR/db/tenet\_db\_$DATE.sql.gz



\# Backup Redis

redis-cli SAVE

cp /var/lib/redis/dump.rdb $BACKUP\_DIR/redis/redis\_$DATE.rdb



\# Backup MinIO data

mc mirror /data/minio $BACKUP\_DIR/minio/



\# Backup configuration files

cp /opt/tenet-ai/.env $BACKUP\_DIR/config/

cp /etc/systemd/system/tenet-\*.service $BACKUP\_DIR/config/



\# Delete old backups

find $BACKUP\_DIR -type f -mtime +$RETENTION\_DAYS -delete



\# Upload to remote storage (S3 example)

aws s3 sync $BACKUP\_DIR s3://your-backup-bucket/tenet-ai/

Cron Job Setup

bash

chmod +x /opt/tenet-ai/scripts/backup.sh

(crontab -l 2>/dev/null; echo "0 2 \* \* \* /opt/tenet-ai/scripts/backup.sh") | crontab -

Recovery Procedure

bash

\# Restore PostgreSQL

gunzip -c $BACKUP\_DIR/db/tenet\_db\_\*.sql.gz | psql -U tenet\_user -d tenet\_db



\# Restore Redis

sudo systemctl stop redis-server

sudo cp $BACKUP\_DIR/redis/redis\_\*.rdb /var/lib/redis/dump.rdb

sudo systemctl start redis-server



\# Restore MinIO

mc mirror $BACKUP\_DIR/minio/ /data/minio/

Incident Response

Common Failure Scenarios \& Remediation

1\. High Latency / Timeouts

Symptoms: API calls > 100ms, dashboard slow

Diagnosis:



bash

docker stats

htop

redis-cli INFO stats

Remediation:



bash

\# Scale up resources

docker-compose up -d --scale ingest=3 --scale analyzer=2



\# Clear Redis cache

redis-cli FLUSHALL



\# Restart services

docker-compose restart ingest analyzer

2\. Model Detection Failures

Symptoms: Increased false positives/negatives

Diagnosis:



bash

python scripts/evaluate\_model.py --test-data data/test\_dataset.json

tail -f logs/analyzer.log | grep "prediction"

Remediation:



bash

\# Retrain model with new data

python scripts/train\_model.py --retrain --data data/new\_attacks.json



\# Rollback to previous model

cp models/trained/model\_backup.pkl models/trained/model.pkl

3\. Database Connection Pool Exhaustion

Symptoms: psycopg2.OperationalError: could not connect to server

Remediation:



bash

\# Increase connection limits

sudo -u postgres psql -c "ALTER SYSTEM SET max\_connections = 200;"

sudo systemctl restart postgresql



\# Or kill idle connections

sudo -u postgres psql -c "SELECT pg\_terminate\_backend(pid) FROM pg\_stat\_activity WHERE state = 'idle';"

4\. Disk Full

Symptoms: Write failures, services crashing

Remediation:



bash

\# Clean Docker

docker system prune -a --volumes -f



\# Rotate logs

find /var/log -name "\*.log" -mtime +7 -delete

journalctl --vacuum-time=7d



\# Move old backups to cold storage

aws s3 mv /backups/tenet-ai/ s3://cold-storage/ --recursive --exclude "\*$(date +%Y%m%d)\*"

5\. Security Breach / Malicious Request Bypass

Symptoms: Unauthorized LLM access, unexpected outputs

Immediate Actions:



bash

\# 1. Block all traffic

sudo ufw deny from any to any port 8000,3000



\# 2. Rotate all secrets

\# Update .env file and restart services

docker-compose down

docker-compose up -d



\# 3. Analyze logs for pattern

grep "blocked: false" /var/log/tenet/\*.log | grep "risk\_score:<0.5"



\# 4. Temporarily switch to strict mode

echo "BLOCK\_ALL\_SUSPICIOUS=true" >> .env

docker-compose restart



\# 5. Contact security team with audit log

python scripts/export\_audit\_log.py --since "24 hours ago" --format csv

Emergency Contacts

Primary: Security Team - security@yourcompany.com



Secondary: DevOps - devops@yourcompany.com



TENET Maintainers: saviodsouza8a@gmail.com



Post-Incident Checklist

Root cause identified



Detection rules updated



Model retrained (if needed)



Backup verified



Documentation updated



Team debrief conducted



text



\### Step 2: Paste into Notepad

\- Open Notepad

\- Press `Ctrl+A` to select any existing text, then `Delete`

\- Press `Ctrl+V` to paste the entire block above



\### Step 3: Save the file

\- Press `Ctrl+S`

\- Make sure the file path is: `C:\\Users\\hp\\OneDrive\\Documents\\TENET\_Ai\\TENET-AI\_arya\_SsoC26\\docs\\production\\deployment-runbook.md`

\- Click Save



\### Step 4: Verify size and update git

```powershell

cd C:\\Users\\hp\\OneDrive\\Documents\\TENET\_Ai\\TENET-AI\_arya\_SsoC26

Get-Item docs\\production\\deployment-runbook.md | Select-Object Length

git add docs\\production\\deployment-runbook.md

git commit --amend --no-edit

git push origin issue-103-deployment-runbook --force

