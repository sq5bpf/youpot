all: certs.pem youpot prereq ssh-mitm


prereq:	
	mkdir -p log patterns_fromclient patterns_fromserver utils

ssh-mitm:
	python3 -m venv utils; . utils/bin/activate; pip install ssh-mitm
	echo -e "\n\n########   Please patch " utils/lib/*/site-packages/sshmitm/session.py " according to the docs"

certs.pem:
	echo "Generating new cert"
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/CN=localhost"
	cat key.pem cert.pem > certs.pem

youpot: youpot.c
	gcc youpot.c -o youpot -lssl -lcrypto -g



