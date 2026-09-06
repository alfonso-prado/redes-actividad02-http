import socket
from dnslib import DNSRecord
from dnslib.dns import CLASS, QTYPE
import dnslib

IP = "192.168.40.115"
PORT = 8000
BUFFER_SIZE = 4096

def send_dns_message(query_name, address, port):
    # Acá ya no tenemos que crear el encabezado porque dnslib lo hace por nosotros, por default pregunta por el tipo A
    qname = query_name
    q = DNSRecord.question(qname)
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # lo enviamos, hacemos cast a bytes de lo que resulte de la función pack() sobre el mensaje
        sock.sendto(bytes(q.pack()), server_address)
        # En data quedará la respuesta a nuestra consulta
        data, _ = sock.recvfrom(BUFFER_SIZE)
        # le pedimos a dnslib que haga el trabajo de parsing por nosotros
        d = DNSRecord.parse(data)
    finally:
        sock.close()
    # Ojo que los datos de la respuesta van en en una estructura de datos
    return d


def print_dns_reply_elements(dnslib_reply):
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

    print(f'SERVER DNS -> {IP}:{PORT}')

    try:
        while True:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)

            print("\n\nMENSAJE DNS RECIBIDO")
            print(f"CLIENTE: {client_address}")
            dns_request = DNSRecord.parse(data)
            print_dns_reply_elements(dns_request)

            query_name = str(dns_request.q.qname)

            dns_reply = send_dns_message(query_name, "1.1.1.1", 53)
            print("\n\nMENSAJE DNS ENVIADO A NAMESERVER")
            print_dns_reply_elements(dns_reply)

            print(f"\n\nRESPUESTA DNS ENVIADO A NAMESERVER A {client_address}")
            print_dns_reply_elements(dns_reply)
            dns_reply.header.id = dns_request.header.id
            server_socket.sendto(
                dns_reply.pack(),
                client_address
            )

    finally:
        server_socket.close()