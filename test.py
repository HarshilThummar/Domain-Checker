from flask import *
import socket
import whois
import requests
import ssl
import nmap
import vulners

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def getValue():
    global ssl_response
    url = request.form['url']
    ip_address = socket.gethostbyname(url)
    domain_name = whois.whois(url).domain_name
    host_name = socket.gethostbyaddr(ip_address)[0]
    server_name = whois.whois(url).get('registrar')
    server_location = whois.whois(url).get('country')
    city = whois.whois(url).get('city')
    state = whois.whois(url).get('state')
    creation_date = whois.whois(url).get('creation_date')
    updated_date = whois.whois(url).get('updated_date')
    expiration_date = whois.whois(url).get('expiration_date')
    api_key = 'YOUR_VULNERS_API_KEY'

    response = requests.get(f"https://{url}", verify=False)

    if response.status_code == 200:
        res = "This URL is Secured"
        ssl_response = "SSL Certified"
    else:
        res = "This URL is not Secured"
        ssl_response = "Isn't SSL Certified"

    scanner = nmap.PortScanner()
    scanner.scan(ip_address, arguments='-p-')
    os_type = scanner[ip_address]['osmatch'][0]['name']

    vulners_api = vulners.Vulners(api_key)
    vuln_results = vulners_api.softwareVulnerabilities(os_type)

    return render_template(
        'pass.html',
        url=url,
        ip_address=ip_address,
        domain_name=domain_name,
        host_name=host_name,
        server_name=server_name,
        server_location=server_location,
        city=city,
        state=state,
        context=ssl,
        res=res,
        ssl_response=ssl_response,
        creation_date=creation_date,
        updated_date=updated_date,
        expiration_date=expiration_date,
        api_key=api_key,
        os_type=os_type,
        vuln_results=vuln_results
    )

if __name__ == '__main__':
    app.run(debug=True)
