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

    # AQUI PUDEMOS VER/MODIFICAR EL MENSAJE DNS USANDO LA LIBRERIA DNSLIB ANTES DE ENVIARLO

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

                ns_reply_byte = resolver(ns_query_byte)
                ns_reply = dns_parser(ns_reply_byte)

                for answer in ns_reply.rr:
                    if QTYPE.get(answer.rtype) == "A":
                        ns_ip = str(answer.rdata)
                        dns_debug(domain, nameserver, ns_ip)
                        # Obtenemos la ip del mensaje de consulta
                        return resolver(mensaje_consulta, ns_ip)

    # Caso D si recibe algún otro tipo de respuesta simplemente la ignora
    # Que se comentan las siguiente lineas a continuacion
    # AQUI PUDEMOS VER/MODIFICAR EL MENSAJE DNS USANDO LA LIBRERIA DNSLIB DESPUES DE ENVIARLO
    # dns_reply_byte = bytes(dns_reply.pack())
    # return dns_reply_byte

def print_dns_message(dnslib_reply):
    # header section
    print(">>--------------- HEADER SECTION ---------------<<\n")
    print("----------- dnslib_reply.header -----------\n{}\n".format(dnslib_reply.header))

    qr_flag = dnslib_reply.header.get_qr()
    print("-> qr_flag = {}".format(qr_flag))

    number_of_query_elements = dnslib_reply.header.q
    print("-> number_of_query_elements = {}".format(number_of_query_elements))

    number_of_answer_elements = dnslib_reply.header.a
    print("-> number_of_answer_elements = {}".format(number_of_answer_elements))

    number_of_authority_elements = dnslib_reply.header.auth
    print("-> number_of_authority_elements = {}".format(number_of_authority_elements))

    number_of_additional_elements = dnslib_reply.header.ar
    print("-> number_of_additional_elements = {}".format(number_of_additional_elements))
    print(">>----------------------------------------------<<\n")

    print(">>---------------- QUERY SECTION ---------------<<\n")
    # query section
    all_querys = dnslib_reply.questions  # lista de objetos tipo dnslib.dns.DNSQuestion
    print("-> all_querys = {}".format(all_querys))

    first_query = dnslib_reply.get_q()  # primer objeto en la lista all_querys
    print("-> first_query = {}".format(first_query))

    domain_name_in_query = first_query.get_qname()  # nombre de dominio por el cual preguntamos
    print("-> domain_name_in_query = {}".format(domain_name_in_query))

    query_class = CLASS.get(first_query.qclass)
    print("-> query_class = {}".format(query_class))

    query_type = QTYPE.get(first_query.qtype)
    print("-> query_type = {}".format(query_type))

    print(">>----------------------------------------------<<\n")

    print(">>---------------- ANSWER SECTION --------------<<\n")
    # answer section
    if number_of_answer_elements > 0:
        all_resource_records = dnslib_reply.rr  # lista de objetos tipo dnslib.dns.RR
        print("-> all_resource_records = {}".format(all_resource_records))

        first_answer = dnslib_reply.get_a()  # primer objeto en la lista all_resource_records
        print("-> first_answer = {}".format(first_answer))

        domain_name_in_answer = first_answer.get_rname()  # nombre de dominio por el cual se está respondiendo
        print("-> domain_name_in_answer = {}".format(domain_name_in_answer))

        answer_class = CLASS.get(first_answer.rclass)
        print("-> answer_class = {}".format(answer_class))

        answer_type = QTYPE.get(first_answer.rtype)
        print("-> answer_type = {}".format(answer_type))

        answer_rdata = first_answer.rdata  # rdata asociada a la respuesta
        print("-> answer_rdata = {}".format(answer_rdata))
    else:
        print("-> number_of_answer_elements = {}".format(number_of_answer_elements))

    print(">>----------------------------------------------<<\n")

    print(">>-------------- AUTHORITY SECTION -------------<<\n")
    # authority section
    if number_of_authority_elements > 0:
        authority_section_list = dnslib_reply.auth  # contiene un total de number_of_authority_elements
        print("-> authority_section_list = {}".format(authority_section_list))

        if len(authority_section_list) > 0:
            authority_section_RR_0 = authority_section_list[0]  # objeto tipo dnslib.dns.RR
            print("-> authority_section_RR_0 = {}".format(authority_section_RR_0))

            auth_type = QTYPE.get(authority_section_RR_0.rtype)
            print("-> auth_type = {}".format(auth_type))

            auth_class = CLASS.get(authority_section_RR_0.rclass)
            print("-> auth_class = {}".format(auth_class))

            auth_time_to_live = authority_section_RR_0.ttl
            print("-> auth_time_to_live = {}".format(auth_time_to_live))

            authority_section_0_rdata = authority_section_RR_0.rdata
            print("-> authority_section_0_rdata = {}".format(authority_section_0_rdata))

            # si recibimos auth_type = 'SOA' este es un objeto tipo dnslib.dns.SOA
            if isinstance(authority_section_0_rdata, dnslib.dns.SOA):
                primary_name_server = authority_section_0_rdata.get_mname()  # servidor de nombre primario
                print("-> primary_name_server = {}".format(primary_name_server))

            elif isinstance(authority_section_0_rdata, dnslib.dns.NS): # si en vez de SOA recibimos un registro tipo NS
                name_server_domain = authority_section_0_rdata  # entonces authority_section_0_rdata contiene el nombre de dominio del primer servidor de nombre de la lista
                print("-> name_server_domain = {}".format(name_server_domain))
    else:
        print("-> number_of_authority_elements = {}".format(number_of_authority_elements))
    print(">>----------------------------------------------<<\n")

    print(">>------------- ADDITIONAL SECTION -------------<<\n")
    if number_of_additional_elements > 0:
        additional_records = dnslib_reply.ar  # lista que contiene un total de number_of_additional_elements DNS records
        print("-> additional_records = {}".format(additional_records))

        first_additional_record = additional_records[0]  # objeto tipo dnslib.dns.RR
        print("-> first_additional_record = {}".format(first_additional_record))

        # En caso de tener additional records, estos pueden contener la IP asociada a elementos del authority section
        ar_class = CLASS.get(first_additional_record.rclass)
        print("-> ar_class = {}".format(ar_class))

        ar_type = QTYPE.get(first_additional_record.rtype)  # para saber si esto es asi debemos revisar el tipo de record
        print("-> ar_type = {}".format(ar_type))

        if ar_type == 'A': # si el tipo es 'A' (Address)
            first_additional_record_rname = first_additional_record.rname  # nombre de dominio
            print("-> first_additional_record_rname = {}".format(first_additional_record_rname))

            first_additional_record_rdata = first_additional_record.rdata  # IP asociada
            print("-> first_additional_record_rdata = {}".format(first_additional_record_rdata))
    else:
        print("-> number_of_additional_elements = {}".format(number_of_additional_elements))
    print(">>----------------------------------------------<<\n")


if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # REMOVER
    # Permite reutilizar rápidamente la dirección/puerto al reiniciar
    # el servidor durante el desarrollo.
    # EVITA... el famoso OSError: [Errno 98] Address already in use
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

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