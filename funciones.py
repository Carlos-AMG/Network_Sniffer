
from termcolor import colored

dns_types = {
    "1": "A",
    "5" : "CNAME",
    "13": "HINFO", 
    "15": "MX",
    "22": "NS",
    "23" : "NS"
}




ports_dict = {
    "20" : "FTP", 
    "21" : "FTP",
    "22" : "SSH",
    "23" : "TELNET",
    "25" : "SMTP",
    "53" : "DNS",
    "67" : "DHCP",
    "68" : "DHCP",
    "69" : "TFTP",
    "80" : "HTTP",
    "110" : "POP3",
    "143" : "IMAP",
    "443" : "HTTPS",
    "993" : "IMAP SSL",
    "995" : "POP SSL"
}


TOS_dict = {"000": "De rutina", #Types of service, ipv4
            "001": "Prioritario",
            "010": "Inmediato",
            "011": "Relampago",
            "100": "Invalidacion relampago",
            "101": "Procesando llamada critica y de emergencia",
            "110": "Control de trabajo de Internet",
            "111": "Control de red"}

hardwareTypes = { #RARP/ARP
    "1": "Ethernet(10 Mb)",
    "6": "IEEE 802 Newtorks",
    "7": "ARCNET",
    "15": "Frame relay",
    "16": "Asynchronous Transfer Mode (ATM)",
    "17": "HDLC",
    "18": "Fibre Channel",
    "19": "Asynchronous Transfer Mode (ATM)",
    "2": "Serial line"
}

protocolos = { #protocolos ipv4
    "1": "ICMPv4",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
    "118": "STP",
    "121": "SMP"
}

TYPE = { #icmpv4
    "0":"Respuesta de eco",
    "3": "Destino inaccesible",
    "4" : "Disminucion de trafico desde el origen",
    "5": "Redireciconar",
    "8" : "Solicitud de eco",
    "11": "Tiempo excedido para datagrama"
}

TYPE_ICMPv6 = { 
    "1": ("Mensaje de destino inalcanzable",{
    "0": "No existe ruta destino",
    "1": "Comunicacion con el destino adrministrativamente prohibida",
    "2" : "No asignado",
    "3" : "Direccion inalcanzable"
    }),
    "2": ("Mensaje de paquete demasiado grande", None),
    "3": ("Time exceeded message",{
    "0": "El limite de tiempo excedido",
    "1": "Tiempo de reensamble de fragmento excedido"
    }),
    "4" : ("Mensaje de problema de parametro",{
    "0": "El campo del encabezado erroneo encontro",
    "1": "El tipo siguiente desconocido del encabezado encontro",
    "2" : "Opcion desconocida del IPV6 encontrada"
    }),
    "128": ("Mensaje del pedido de eco", None),
    "129" : ("Mensaje de respuesta de eco", None),
    "133": ("Mensaje de solicitud del router", None),
    "134": ("Mensaje de anuncio del router", None),
    "135" : ("Mensaje de solicitud vecino", None),
    "136": ("Mensaje de anuncio de vecino", None),
    "137": ("Reoriente el mensaje", None)
}


CODE = { #impv4
    "0":"No se puede llegar a la red",
    "1": "No se puede llegar al host",
    "2" : "Destino no dispone del protocolo solicitado",
    "3": "No se puede llegar al puerto de destino o la aplicacion destino no esta libre",
    "4" : "Se necesita aplicar fragmentacion, pero el flag correspondiente indica lo contrario",
    "5": "La ruta de origen no es correcta"
}



def imprimirDatos(lista, **kwargs):
    """Usar name= para el positional argument y espera los siguientes valores: Source, Target, Type, Data"""
    current_name = ""
    source = 0
    target = 0
    if kwargs["name"] == "Target":
        current_name = kwargs["name"] + " MAC Address"
        source = 0
        target = 6
    elif kwargs["name"] == "Source":
        current_name = kwargs["name"] + " MAC Address"
        source = 6
        target = 12
    elif kwargs["name"] == "Type":
        current_name = kwargs["name"]
        source = 12
        target = 14
    elif kwargs["name"] == "Data":
        current_name = kwargs["name"]
        source = 0
        target = len(lista)
    datos = ""
    for x in range(source, target):
        if x == source or x == target:
            datos += lista[x].zfill(2)
        else:
            datos += ":" + lista[x].zfill(2)
    return (f"{current_name}: {datos}")


def toBinary(number, digits=8):
    return bin(int(number, 16))[2:].zfill(digits)


def TOS(numero):
    datos = toBinary(numero, 8)
    print("Prioridad:", TOS_dict[datos[0:3]])
    if datos[3] == "0":
        print("Retardo: Normal")
    else:
        print("Retardo: Bajo")
    if datos[4] == "0":
        print("Rendimiento: Normal")
    else:
        print("Rendimiento: Alto")
    if datos[5] == "0":
        print("Fiabilidad: Normal")
    else:
        print("Fiabilidad: Bajo")


def banderasAndFragmento(numero):
    binario = toBinary(numero, 16)
    print("banderas:")
    if binario[0] == "0":
        print(" *Reservado")
    else:
        print("none")
    if binario[1] == "0":
        print(" *Divisible")
    else:
        print(" *No Divisible")
    if binario[2] == "0":
        print(" *Ultimo Fragmento")
    else:
        print(" *Fragmento Intermedio")
    print("Posicion de fragmento:", int(binario[3:], 2))


def CrearDireccion(numero):
    binario = toBinary(numero, 32)
    IP = str(int(binario[0:8], 2)) + "." + str(int(binario[8:16], 2)) + "." + str(int(binario[16:24], 2)) + "." + str(int(binario[24:32], 2))
    return  IP

def deleteElements(lista, numero):
    for x in range(0, numero):
        lista.remove(lista[0])

def compararICMP(data, type=0):
    informacion = str(int(data, 16))
    if type == 0:
        print("Mensaje informativo:", TYPE[informacion])
    else:
        print("Codgigos de error:", CODE[informacion])

def opcode(lista): #para rarp/arp
    temporal = int(lista[0] + lista[1], 10)
    if temporal == 1:
        return "Solicitud ARP"
    elif temporal == 2:
        return "Respuesta ARP"
    elif temporal == 3:
        return "Solitud RARP"
    elif temporal == 4:
        return "Respuesta RARP"

def CodeAddresses(lista, bytes, hex=True):
    direccion = ""
    if hex:
        for x in range(0, bytes):
            if x == 0 or x == bytes:
                direccion += lista[x].zfill(2)
            else:
                direccion += ":" + lista[x].zfill(2)
        return direccion
    else:
        binario = toBinary(lista[0] + lista[1] + lista[2] + lista[3])
        IP = str(int(binario[0:8], 2)) + "." + str(int(binario[8:16], 2)) + "." + str(int(binario[16:24], 2)) + "." + str(int(binario[24:32], 2))
        return  IP

def compararICMPV6(data, choice=True):
    byte1 = str(int(data[:2], 16))
    byte2 = str(int(data[2:4], 16))
    aux = TYPE_ICMPv6[byte1]
    print("Tipo:", aux[0])
    if aux[1]:
        print("Codigo:", aux[1][byte2])

def puertos(data):
    """Para TCP tanto para ipv4 e ipv6"""
    num = (int(data, 16))
    if (0 <= num <= 1023):
        num = str(num)
        temp = f"{num} - Puertos bien conocidos: " + ports_dict[num]
        return  temp
    elif ( 1024 <= num <= 49151):
        return (f"{num} - Puertos registrados")
    elif (49152 <= num <= 65535):
        return (f"{num} - Puertos dinamicos o privados")


def DNS(lista_copia, lista_original):
    print("\tDNS")
    variables_dns = {}
    preguntas_dns = {}
    respuestas_dns = {}
    lista_copia = lista_copia[:]
    print("ID:", lista_copia[0] + lista_copia[1])
    deleteElements(lista_copia, 2)
    bin_aux = toBinary(lista_copia[0] + lista_copia[1], 16)
    print("QR:", "Respuesta" if bin_aux[0] == "1" else "Consulta")
    bin_aux = bin_aux[1:]
    opcode_dec = int(bin_aux[:5], 16)
    if (opcode_dec == 0):
        opcode_aux = "QUERY"
    elif (opcode_dec == 1):
        opcode_aux = "IQUERY"
    elif (opcode_dec == 2):
        opcode_aux = "STATUS"
    else:
        opcode_aux = "UNDEFINED"
    print("Op code:", opcode_aux)
    bin_aux = bin_aux[4:]
    print("AA:", "Respuesta" if bin_aux[0] == "1" else "Sin respuesta")
    bin_aux = bin_aux[1:]
    print("TC:", "Mensaje demasiado largo" if bin_aux[0] == "1" else "Mensaje permitido")
    bin_aux = bin_aux[1:]
    print("RD:", bin_aux[0]) #preguntar por todas estas banderas
    bin_aux = bin_aux[1:]
    print("RA:", bin_aux[0])
    bin_aux = bin_aux[1:]
    print("Z:", bin_aux[:4])
    bin_aux = bin_aux[3:]
    rcode_dec = int(bin_aux[:5], 16)
    if (rcode_dec == 0):
        rcode_aux = "Ningun error"
    elif (rcode_dec == 1):
        rcode_aux = "Error de formato"
    elif (rcode_dec == 2):
        rcode_aux = "Fallo en el servidor"
    elif (rcode_dec == 3):
        rcode_aux = "Error en nombre"
    elif (rcode_dec == 4):
        rcode_aux = "No implementado"
    elif (rcode_dec == 5):
        rcode_aux = "Rechazado"
    else:
        rcode_aux = "UNDEFINED"
    print("Rcode:", rcode_aux)
    bin_aux = bin_aux[4:]
    deleteElements(lista_copia, 2)
    print("QDcount:", int(lista_copia[0] + lista_copia[1], 16))
    preguntas = int(lista_copia[0] + lista_copia[1], 16)
    deleteElements(lista_copia, 2)
    print("ANcount:", int(lista_copia[0] + lista_copia[1], 16))
    respuestas = int(lista_copia[0] + lista_copia[1], 16)
    deleteElements(lista_copia, 2)
    print("NScount:", int(lista_copia[0] + lista_copia[1], 16))
    deleteElements(lista_copia, 2)
    print("ARcount:", int(lista_copia[0] + lista_copia[1], 16))
    deleteElements(lista_copia, 2)

    # aqui sacamos los hex para luego formar el ascii
    """Copiamos la lista por si acaso y trabajamos con esa"""
    counter = 0
    array = []
    for _ in range(0, preguntas):
        array.clear()
        array.append("Nombre de dominio: " + to_ascii(lista_copia))
        deleteElements(lista_copia, 1)
        array.append("Tipo: " +  dns_types[str(int(lista_copia[0] + lista_copia[1], 16))])
        deleteElements(lista_copia, 2)
        array.append("Clase: " + "IN" if int(lista_copia[0] + lista_copia[1], 16) == 1 else "CH")
        deleteElements(lista_copia, 2)
        copia = array[:]
        preguntas_dns[f"pregunta{counter}"] = copia
        counter += 1
    print(colored("Preguntas", "blue"))
    for x in preguntas_dns:
        print(x + ":")
        for y in preguntas_dns[x]:
            print(y)
    # print(preguntas_dns)
    # print("current list", lista_copia)
    
    counter = 0
    seek_pos = int(lista_copia[0] + lista_copia[1], 16)
    print(colored("This is the seek position " + str(seek_pos), "blue"))
    # print("Lista original", lista_original)
    flag = True
    for _ in range(0, respuestas):
        array.clear()
        lista_original_copia = lista_original[seek_pos - 1:]
        array.append("Nombre de dominio: " + to_ascii(lista_original_copia))
        if (flag):
            deleteElements(lista_original_copia,1 + 6)
        else:
            deleteElements(lista_original_copia, 2)
        # print("Lista original copia ->>>>>>>>>>>>:", lista_original_copia)
        """Aqui abajo esta el problema, necesitamos arreglar cuando no es direccion con puntos, en el to_ascii tenemos que arreglar
        que si no es de punto, haga otra cosa"""
        respuestas_type = dns_types[str(int(lista_original_copia[0] + lista_original_copia[1], 16))] 
        print(colored(respuestas_type, "green"))
        array.append("Tipo de respuesta: " + respuestas_type)
        deleteElements(lista_original_copia, 2)
        array.append("Clase: " + str(int(lista_original_copia[0] + lista_original_copia[1], 16)))
        deleteElements(lista_original_copia, 2)
        # print("Lista original copia ->>>>>>>>>>>>:", lista_original_copia)
        array.append("Tiempo de vida: " + str(int(lista_original_copia[0] + lista_original_copia[1] + lista_original_copia[2] + lista_original_copia[3], 16)))
        deleteElements(lista_original_copia, 4)
        array.append("Longitud de datos: " + str(int(lista_original_copia[0] + lista_original_copia[1], 16)))
        deleteElements(lista_original_copia, 2)
        if (respuestas_type == "A"):
            array.append("RDATA: " + CrearDireccion(lista_original_copia[0] + lista_original_copia[1] + lista_original_copia[2] + lista_original_copia[3]))
        elif (respuestas_type == "CNAME"):
            array.append("RDATA: " + to_ascii(lista_original_copia))
        elif (respuestas_type == "MX"):
            pass
        elif (respuestas_type == ""):
            pass
        seek_pos = int(lista_original_copia[0] + lista_original_copia[1], 16)
        copia = array[:]
        respuestas_dns[f"respuesta{counter}"] = copia
        # print(respuestas_dns)
        counter += 1
        flag = False
    print(colored("Respuestas", "blue"))
    for x in respuestas_dns:
        print(x + ":")
        for y in respuestas_dns[x]:
            print(y)
    # print(imprimirDatos(lista_original_copia, name="Data"))
    # print(imprimirDatos(lista_original_copia, name="Data"))
    # print(imprimirDatos(lista_copia, name="Data"))

def to_ascii(lista_copia):
    flag = False
    contador = 1
    variables_dns = {}
    copied = lista_copia[:]
    while copied[0] != "00":
        saltos = int(copied[0], 16)
        try:
            # deleteElements(copied, saltos + 1)
            for x in range(0, saltos + 1):
                copied.pop(0)
        except:
            name = ""
            contador = int(lista_copia[0], 16)
            lista_copia.pop(0)
            for x in range(0 , contador):
                name += str(bytes.fromhex(lista_copia[0]).decode("ASCII"))
                lista_copia.pop(0)
            lista_copia.pop(0)
            lista_copia.pop(0)
            return name
        #aqui hacer lo del punto en la actual
    while lista_copia[0] != "00":
        saltos = int(lista_copia[0], 16)
        variables_dns[f"variable{contador -1}"] = lista_copia[1:saltos + 1]
        contador += 1
        deleteElements(lista_copia, saltos + 1)
    #aqui ya formamos el ascii
    domain = ""
    for keys in variables_dns:
        for values in variables_dns[keys]:
            domain += str(bytes.fromhex(values).decode("ASCII")) #esto por usar python3 sino usar metodo decode(hex)
        domain += "."
    domain  = domain[:-1]
    # lista_copia.remove(lista_copia[0])
    return domain