gunicorn server2.wsgi:application   --bind 0.0.0.0:8081   --certfile ../server2.crt   --keyfile ../server2.key   --ca-certs ../ca.crt   --cert-reqs 2   --ciphers 'ECDHE+AESGCM'




python mtls_client.py --host localhost --port 8081 --path /api/server-time/

python peds_encrypt_client.py


sudo wireshark
tcp.port == 8081