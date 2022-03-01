### Build:
`docker build -t gitflow-nginx:1.20.2-1 .`
  
### Run:  
`docker run --name my-flow --rm -p 8000:8080 -p 4443:8443 gitflow-nginx:1.20.2-1` 

Exposes 8080 & 8443


Navigate with your browser to view the running nginx server
http://localhost:8000/