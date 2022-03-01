"""
Equipo 3
Carlos Alberto Martinez Gallegos
Ricardo Perez Ortiz
Daniel Garcia Tovar
Miriam Paola Rodriguez Martin
"""
from ctypes.wintypes import PFILETIME
import funciones as funct
lista_datos = []
lista_IP = []
dicc_paraARP = funct.hardwareTypes
dict_type = {"08:00": "IPv4", #para ethernet
             "08:06": "ARP",
             "80:35": "RARP",
             "86:dd": "IPv6"}
with open("./Files/ipv6_icmpv6_ping.bin", mode="rb") as file:
    content = file.read()
    for _bytes in content:
        lista_datos.append(hex(_bytes)[2:].zfill(2))
    lista_IP = lista_datos[14:]
    print("\tEthernet")
    print(funct.imprimirDatos(lista_datos, name="Target"))
    print(funct.imprimirDatos(lista_datos, name="Source"))
    print(funct.imprimirDatos(lista_datos, name="Type"), dict_type[f'{lista_datos[12]}:{lista_datos[13]}'])
    #print(funct.imprimirDatos(lista_datos, name="Data"))
    if (dict_type[f'{lista_datos[12]}:{lista_datos[13]}'] == "IPv4"):
        print("\tIPv4")
        print("Version:", (lista_IP[0])[0])
        print("Tamano:", (lista_IP[0])[1], "palabras")
        lista_IP.remove(lista_IP[0])
        funct.TOS(lista_IP[0])
        lista_IP.remove(lista_IP[0])
        print("Longitud del paquete:", int(lista_IP[0]+lista_IP[1], 16), "octetos")
        funct.deleteElements(lista_IP, 2)
        print("Identificador:", int(lista_IP[0] + lista_IP[1], 16))
        funct.deleteElements(lista_IP, 2)
        funct.banderasAndFragmento(lista_IP[0] + lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print("Tiempo de vida:", int(lista_IP[0], 16))
        lista_IP.remove(lista_IP[0])
        print("Protocolo:", funct.protocolos[str(int(lista_IP[0], 16))])
        lista_IP.remove(lista_IP[0])
        print("Checksum:", lista_IP[0], lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print("Direccion IP de origen:", funct.CrearDireccion(lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]))
        funct.deleteElements(lista_IP, 4)
        print("Direccion IP de destino:", funct.CrearDireccion(lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]))
        funct.deleteElements(lista_IP, 4)
        funct.compararICMP(lista_IP[0], 0)
        lista_IP.remove(lista_IP[0])
        funct.compararICMP(lista_IP[0], 1)
        lista_IP.remove(lista_IP[0])
        print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print(funct.imprimirDatos(lista_IP, name="Data"))
    elif (dict_type[f'{lista_datos[12]}:{lista_datos[13]}'] == "ARP" or dict_type[f'{lista_datos[12]}:{lista_datos[13]}'] == "RARP"):
        print(dict_type[f'{lista_datos[12]}:{lista_datos[13]}'])
        print("Tipo de hardware:", dicc_paraARP[f'{int(lista_IP[0] + lista_IP[1], 10)}'] )
        funct.deleteElements(lista_IP, 2)
        print("Tipo de protocolo: ", f'{lista_IP[0]}:{lista_IP[1]}', dict_type[f'{lista_IP[0]}:{lista_IP[1]}'])
        funct.deleteElements(lista_IP, 2)
        print("Longitud direccion de hardware:", lista_IP[0])
        print("Longitud direccion de protocolo:", lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print("Codigo de operacion:", funct.opcode(lista_IP))
        funct.deleteElements(lista_IP, 2)
        print("Direccion hardware del emisor:", funct.CodeAddresses(lista_IP, 6))
        funct.deleteElements(lista_IP, 6)
        print("Direccion IP del emisor:", funct.CodeAddresses(lista_IP, 4, False))
        funct.deleteElements(lista_IP, 4)
        print("Direccion hardware del receptor:", funct.CodeAddresses(lista_IP, 6))
        funct.deleteElements(lista_IP, 6)
        print("Direccion Ip del receptor:", funct.CodeAddresses(lista_IP, 4, False))
        funct.deleteElements(lista_IP, 4)
        print(lista_IP)   
    if (dict_type[f'{lista_datos[12]}:{lista_datos[13]}'] == "IPv6"):
        print("\tIPv6")
        print("Version:", (lista_IP[0])[0])
        funct.TOS(lista_IP[0][1] + lista_IP[1][0])
        print("Etiqueta de flujo: " + str(int(lista_IP[1][1] + lista_IP[2] + lista_IP[3], 2)))#hacer funcion en caso de necesitar convertir bin a decimal
        funct.deleteElements(lista_IP, 4)
        print("Tamano de datos:", int(lista_IP[0]+lista_IP[1], 16), "octetos")
        funct.deleteElements(lista_IP, 2)
        print("Encabezado siguiente:", funct.protocolos[str(int(lista_IP[0], 16))]) #icmpv6
        lista_IP.remove(lista_IP[0])
        print("Limite de salto:", int(lista_IP[0], 16))
        lista_IP.remove(lista_IP[0])
        print("Direccion de origen:", funct.CodeAddresses(lista_IP, 16))
        funct.deleteElements(lista_IP, 16)
        print("Direccion de destino:", funct.CodeAddresses(lista_IP, 16))
        funct.deleteElements(lista_IP, 16)
        print(funct.imprimirDatos(lista_IP, name="Data"))
        funct.compararICMPV6(lista_IP[0] + lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print("Checksum:", lista_IP[0] + ":" + lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print(lista_IP)
        #print("Protocolo:", funct.protocolos[str(int(lista_IP[0], 16))])
        


