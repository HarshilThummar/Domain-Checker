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
    api_key = whois.whois(url).get('YOUR_VULNERS_API_KEY')
    
    # response = requests.get(url)  
    # server_header = response.headers.get("Server")
    response = requests.get(f"https://{url}", verify=False)

    if response.status_code == 200:
        res = "This URL is Secured"
        ssl_response = "SSL Certified"
    else:
        res = "This URL is not S`ecured"
        ssl_response = "Isn't SSL Certified"

    # if response.status_code == 200:
    #     try:
    #         # Attempt to create an SSL context
    #         context = ssl.create_default_context()
    #         context.check_hostname = False
    #         context.verify_mode = ssl.CERT_REQUIRED

    #         # Verify SSL certificate
    #         ssl.match_hostname(context, response.url)
    #         ssl_response = f"{response.url} is SSL certified!"
    #     except ssl.SSLError:
    #         ssl_response = f"{response.url} is NOT SSL certified."
    # else:
    #     ssl_response = f"Unable to check SSL certification for {response.url}. Status code: {response.status_code}"

    # scanner = nmap.PortScanner()
    # scanner.scan(host, arguments='-p-')
    # os = scanner[host]['osmatch'][0]['name']
    # print("The web server is running on:", os)

    # Check if SSL certificate is present

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
        api_key=api_key
        # server_header=server_header,
    )

    #     def check_ssl_cert(url):
    #     # Extract the hostname from the URL
    #         hostname = url.split("//")[-1].split("/")[0]

    #         # Set up a socket connection to the SSL port of the server
    #         context = ssl.create_default_context()
    #         conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    #         conn.connect((hostname, 443))

    #         # Get the SSL certificate details
    #         cert = conn.getpeercert()

    #         # Check the certificate expiration date
    #         expiration_date = cert['notAfter']
    #         print(f"Certificate expiration date: {expiration_date}")
                
    #         # Check the issuer of the certificate
    #         issuer = cert['issuer']
    #         print(f"Certificate issuer: {issuer}")

    #         # Close the connection
    #         conn.close()
    # except Exception as e:
    #     return render_template(
    #         'templates\index.html',
    #         url=url,
    #         error_message=str(e),
    #     )

        # def get_os_type(url):
        #     # Get the IP address of the URL
        #         ip_address = socket.gethostbyname(url)
                
        #         # Get the domain name of the URL
        #         domain_name = whois.whois(url).domain_name
                
        #         # Use nmap to scan for open ports and OS detection
        #         scanner = nmap.PortScanner()
        #         scanner.scan(ip_address, arguments='-O')
                
        #         # Get the OS type from the scan results
        #         os_type = scanner[ip_address]['osmatch'][0]['name']
                
        #         # return os_type
        #         print(os_type)

if __name__ == '__main__':  
    app.run(debug=True)

