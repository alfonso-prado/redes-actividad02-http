import socket
from dnslib import DNSRecord
from dnslib.dns import CLASS, QTYPE
import dnslib
from dnslib.dns import RR, A

IP = "192.168.40.115"
PORT = 8000
BUFFER_SIZE = 4096
DNS_SERVER_IP="199.7.83.42"
DNS_SERVER_NAMESERVER="."

# Diccionario que guarda los últimos 3 dominios que más se repiten.
# La key es el dominio y el value es la ip
cache = dict()
# Cola que contiene las última 20 consultas.
last_20_domains = []
# Contador de dominios, cuenta de las última 20 consultas
# que dominios son los más consultados
# La key es el dominio y el value es la cantidad de veces que se ha consultado
domain_counts = dict()

# Esta funcion actualiza cache, last_20_domains y domains_counts
# con el dominio consultado. La función se llama cada vez que 
# se consulta un dominio.
# Si el dominio consultado queda en los top 3 la función
# actualiza el cache con el dominio y su ip
def cache_domain(domain, ip):
    # Agrega al principio de la cola el dominio entrante
    last_20_domains.append(domain)
    # Suma uno al dominio que está en domain_counts, con eso se tiene un registro 
    # de los dominios más consultados dentro de las últimas 20 consultas
    domain_counts[domain] = domain_counts.get(domain, 0) + 1

    # Si la cola tiene más de 20 elementos se elimina la consulta más antigua
    if len(last_20_domains) > 20:
        domain_removed = last_20_domains.pop(0)
        # Gestión del contador de los dominios más consultados (domain_counts)
        if domain_removed not in last_20_domains: 
            # Para el caso de que si el dominio no se encuentra en last_20_domains
            # se elimina de domain_removed
            domain_counts.pop(domain_removed, None)
        else:
            # En caso contrario se disminuye en uno
            counts = domain_counts.get(domain_removed) - 1
            domain_counts[domain_removed] = counts

    # Creamos una lista ordenada de los dominios mas consultados a los menos consultados.
    ordered_domains = sorted(
        domain_counts,
        key=domain_counts.get,
        reverse=True
    )

    # Obtenemos los 3 dominios más consultados
    top3 = ordered_domains[:3]

    # Obtenemos los dominios en cache que ya no son los más consultados
    expire_domains = set(cache) - set(top3) 

    # Eliminamos esos dominios del cache
    for expire_domain in expire_domains:
        cache.pop(expire_domain, None)

    # Si el nuevo dominio consultado está en el top 3, entonces 
    # lo agregamos al cache
    if domain in top3:
        cache[domain] = ip
 
# Obtiene el ip del dominio almacenado en el cache, si no está en cache devuelve None
def cache_get_domain_ip(domain):
    ip = cache.get(domain)
    return ip

def dns_parser(data):
    return DNSRecord.parse(data)

def send_dns_message(message: bytes, address, port) -> bytes:
    # Acá ya no tenemos que crear el encabezado porque dnslib lo hace por nosotros, por default pregunta por el tipo A
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # lo enviamos, hacemos cast a bytes de lo que resulte de la función pack() sobre el mensaje
        sock.sendto(message, server_address)
        # En data quedará la respuesta a nuestra consulta
        data, _ = sock.recvfrom(BUFFER_SIZE)
    finally:
        sock.close()
    # Ojo que los datos de la respuesta van en en una estructura de datos
    return data

def dns_debug(domain, nameserver = None, ip = None):
    if not nameserver and not ip:
        print(f"(debug) Consultando '{domain}' a cache del resolver")
    else:
        print(f"(debug) Consultando '{domain}' a '{nameserver}' con dirección IP '{ip}'")       

def resolver(mensaje_consulta: bytes, ip_addr) -> bytes:
    # Convertimos mensaje_consulta en byte a la estructura de datos de DNSLibs
    dns_request = dns_parser(mensaje_consulta)

    # DEBUG
    domain = str(dns_request.q.qname)
    if ip_addr == DNS_SERVER_IP:
        dns_debug(domain, DNS_SERVER_NAMESERVER, ip_addr)

    # Convertimos la estructura de DNSLibs a bytes
    dns_request_byte = bytes(dns_request.pack())
    # Enviamos el mensaje DNS a Nameserver con el ip_addr
    dns_reply_byte = send_dns_message(dns_request_byte, ip_addr, 53)

    # Convertimos dns_reply_byte a la estructura de datos de DNSLibs
    dns_reply = dns_parser(dns_reply_byte)

    # B de parte 4
    # Si encuentra RR A en Answer termina y vuelve resultado
    number_of_answer_elements = dns_reply.header.a
    if number_of_answer_elements > 0:
        for answer in dns_reply.rr:    
            if QTYPE.get(answer.rtype) == "A":     
                return dns_reply_byte

    # C de parte 4
    # Sucede cuando no anwer no tiene RR A pero si Auth tine RR NS
    # Significa que está delegando a otro nameserver
    number_of_authority_elements = dns_reply.header.auth
    if number_of_authority_elements > 0:
        # Los RR de auth para el caso NS son de la forma por ej:
        # ejemplo.cl.   NS   ns1.ejemplo.cl.
        for auth in dns_reply.auth:
            # Caso C.I: busca IP en Additional
            # El RR de auth es NS y existe al menos un RR additional
            if QTYPE.get(auth.rtype) == "NS": 
                nameserver = str(auth.rdata) 

                # Los RR de additional para el caso de A son de la forma por ej:
                # ns1.ejemplo.cl.   A   1.2.3.4
                number_of_additional_elements = dns_reply.header.ar
                if number_of_additional_elements > 0:
                    for additional in dns_reply.ar:
                        # Dato adiccional que tiene RR tipo A que contiene la IP del NS
                        rname = str(additional.rname) 
                        # Tiene que ser RR A pero tambien tiene que tener mismo rname que nameserver
                        if QTYPE.get(additional.rtype) == "A" and rname == nameserver:
                            ns_ip = str(additional.rdata)
                            dns_debug(domain, nameserver, ns_ip)
                            # Obtenemos la ip del mensaje de consulta
                            return resolver(mensaje_consulta, ns_ip)

                # Si se llega hasta aqui es porque no existe Additional con un registro A con la IP del NS 
                # Caso C.II: resuelve la ip del NS
                # Creamos el RR para hacer la question sobre la ip del nameserver
                ns_query = DNSRecord.question(nameserver)
                ns_query_byte = bytes(ns_query.pack())

                ns_reply_byte = resolver(ns_query_byte, DNS_SERVER_IP)
                ns_reply = dns_parser(ns_reply_byte)

                for answer in ns_reply.rr:
                    if QTYPE.get(answer.rtype) == "A":
                        ns_ip = str(answer.rdata)
                        dns_debug(domain, nameserver, ns_ip)
                        # Obtenemos la ip del mensaje de consulta
                        return resolver(mensaje_consulta, ns_ip)

    # Caso D si recibe algún otro tipo de respuesta simplemente la ignora

if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    socket_address = (IP, PORT)
    server_socket.bind(socket_address)

    print(f'RESOLVER DNS ON -> {IP}:{PORT}')

    try:
        while True:
            # Recibimos de cliente
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)

            # Datos necesario para usar cache
            data_request = dns_parser(data)
            qname = data_request.q.qname
            domain = str(qname)
            # Obtener cache
            cached_ip = cache_get_domain_ip(domain)
            if cached_ip is not None:
                # Crear mensaje DNS con el cache obtenido
                dns_debug(domain)
                dns_reply = data_request.reply()
                dns_reply.add_answer(RR(qname, QTYPE.A, rdata=A(cached_ip)))
                dns_reply_byte = bytes(dns_reply.pack())
            else:
                # Usar resolver si no está el dominio en el cache
                dns_reply_byte = resolver(data, DNS_SERVER_IP)

            # Actualizar cache
            dns_reply = dns_parser(dns_reply_byte)
            for answer in dns_reply.rr:
                if QTYPE.get(answer.rtype) == "A":
                    ip = str(answer.rdata)
                    cache_domain(domain, ip)

            # Enviamos a cliente
            server_socket.sendto(
                dns_reply_byte,
                client_address
            )

    finally:
        server_socket.close()