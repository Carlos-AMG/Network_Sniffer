TOS_dict = {"000": "De rutina",
            "001": "Prioritario",
            "010": "Inmediato",
            "011": "Relampago",
            "100": "Invalidacion relampago",
            "101": "Procesando llamada critica y de emergencia",
            "110": "Control de trabajo de Internet",
            "111": "Control de red"}

protocolos = {
    "1": "ICMPv4",
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
    "118": "STP",
    "121": "SMP"
}

TYPE = {
    "0":"Respuesta de eco",
    "3": "Destino inaccesible",
    "4" : "Disminucion de trafico desde el origen",
    "5": "Redireciconar",
    "8" : "Solicitud de eco",
    "11": "Tiempo excedido para datagrama"
}

CODE = {
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