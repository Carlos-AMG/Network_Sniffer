"""
Equipo 3
Carlos Alberto Martinez Gallegos
Ricardo Perez Ortiz
Daniel Garcia Tovar
Miriam Paola Rodriguez Martin
"""
from base64 import decode
from ctypes.wintypes import PFILETIME
from encodings import utf_8
from xml import dom
import funciones as funct

protocolo_actual = ""
variables_dns = {
}
lista_datos = []
lista_IP = []
dicc_paraARP = funct.hardwareTypes
dict_type = {"08:00": "IPv4", #para ethernet
             "08:06": "ARP",
             "80:35": "RARP",
             "86:dd": "IPv6"}
with open("Files/ethernet_ipv4_udp_dns.bin", mode="rb") as file:
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
        protocolo_actual = funct.protocolos[str(int(lista_IP[0], 16))]
        print("Protocolo:", protocolo_actual)
        lista_IP.remove(lista_IP[0])
        print("Checksum:", lista_IP[0], lista_IP[1])
        funct.deleteElements(lista_IP, 2)
        print("Direccion IP de origen:", funct.CrearDireccion(lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]))
        funct.deleteElements(lista_IP, 4)
        print("Direccion IP de destino:", funct.CrearDireccion(lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]))
        funct.deleteElements(lista_IP, 4)
        if protocolo_actual == "ICMPv4":
            funct.compararICMP(lista_IP[0], 0)
            lista_IP.remove(lista_IP[0])
            funct.compararICMP(lista_IP[0], 1)
            lista_IP.remove(lista_IP[0])
            print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
            funct.deleteElements(lista_IP, 2)
        elif protocolo_actual == "TCP":
            print("\tTCP")
            print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            temp = lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]
            print("Numero de secuencia:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 4)
            temp = lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]
            print("Numero de acuse de recibo:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 4)
            print("Longitud de cabecera:", (int(lista_IP[0][0], 16)), "palabras")
            binario = funct.toBinary(lista_IP[0][1], 4)
            print("NS:", binario[-1])
            lista_IP.remove(lista_IP[0])
            binario = funct.toBinary(lista_IP[0], 8)
            print("CWR:", binario[0])
            print("ECE:", binario[1])
            print("URG:", binario[2])
            print("ACK:", binario[3])
            print("PSH:", binario[4])
            print("RST:", binario[5])
            print("SYN:", binario[6])
            print("FIN:", binario[7])
            lista_IP.remove(lista_IP[0])
            temp = lista_IP[0] + lista_IP[1] 
            print("Tamano de ventana:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 2)
            print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
            funct.deleteElements(lista_IP, 2)
            if binario[2] == "1":
                temp = lista_IP[0] + lista_IP[1]
                print("Puntero urgente:", (int(temp, 16)))
            else:
                pass
            funct.deleteElements(lista_IP, 2)
        elif protocolo_actual == "UDP":
            print("\tUDP")
            print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
            auxiliar_portv = int(lista_IP[0] + lista_IP[1], 16)
            funct.deleteElements(lista_IP, 2)
            temp = lista_IP[0] + lista_IP[1] 
            print("Longitud total:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 2)
            print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
            funct.deleteElements(lista_IP,2)
            if auxiliar_portv == 53:
                print("\tDNS")
                print("ID:", lista_IP[0] + lista_IP[1])
                funct.deleteElements(lista_IP, 2)
                bin_aux = funct.toBinary(lista_IP[0] + lista_IP[1], 16)
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
                funct.deleteElements(lista_IP, 2)
                print("QDcount:", int(lista_IP[0] + lista_IP[1], 16))
                funct.deleteElements(lista_IP, 2)
                print("ANcount:", int(lista_IP[0] + lista_IP[1], 16))
                funct.deleteElements(lista_IP, 2)
                print("NScount:", int(lista_IP[0] + lista_IP[1], 16))
                funct.deleteElements(lista_IP, 2)
                print("ARcount:", int(lista_IP[0] + lista_IP[1], 16))
                funct.deleteElements(lista_IP, 2)
                # aqui sacamos los hex para luego formar el ascii
                """Copiamos la lista por si acaso y trabajamos con esa"""
                lista_copia = lista_IP[:]
                contador = 1
                while lista_copia[0] != "00":
                    saltos = int(lista_copia[0], 16)
                    print(saltos)
                    variables_dns[f"variable{contador -1}"] = lista_copia[1:saltos + 1]
                    contador += 1
                    funct.deleteElements(lista_copia, saltos + 1)
                #aqui ya formamos el ascii
                print(variables_dns)
                domain = ""
                for keys in variables_dns:
                    for values in variables_dns[keys]:
                            domain += str(bytes.fromhex(values).decode("ASCII")) #esto por usar python3 sino usar metodo decode(hex)
                    domain += "."
                domain  = domain[:-1]
                print(domain)
        print(funct.imprimirDatos(lista_copia, name="Data"))
        # print(funct.imprimirDatos(lista_IP, name="Data"))
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
        print(funct.imprimirDatos(lista_IP, name="Data"))
        # print(lista_IP)   
    if (dict_type[f'{lista_datos[12]}:{lista_datos[13]}'] == "IPv6"):
        print("\tIPv6")
        print("Version:", (lista_IP[0])[0])
        funct.TOS(lista_IP[0][1] + lista_IP[1][0])
        print("Etiqueta de flujo: " + str(int(lista_IP[1][1] + lista_IP[2] + lista_IP[3], 2)))#hacer funcion en caso de necesitar convertir bin a decimal
        funct.deleteElements(lista_IP, 4)
        print("Tamano de datos:", int(lista_IP[0]+lista_IP[1], 16), "octetos")
        funct.deleteElements(lista_IP, 2)
        protocolo_actual = funct.protocolos[str(int(lista_IP[0], 16))] 
        print("Encabezado siguiente:", protocolo_actual) #icmpv6
        lista_IP.remove(lista_IP[0])
        if protocolo_actual == "ICMPv6":
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
        elif protocolo_actual == "TCP":
            print("\tTCP")
            print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            temp = lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]
            print("Numero de secuencia:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 4)
            temp = lista_IP[0] + lista_IP[1] + lista_IP[2] + lista_IP[3]
            print("Numero de acuse de recibo:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 4)
            print("Longitud de cabecera:", (int(lista_IP[0][0], 16)), "palabras")
            binario = funct.toBinary(lista_IP[0][1], 4)
            print("NS:", binario[-1])
            lista_IP.remove(lista_IP[0])
            binario = funct.toBinary(lista_IP[0], 8)
            print("CWR:", binario[0])
            print("ECE:", binario[1])
            print("URG:", binario[2])
            print("ACK:", binario[3])
            print("PSH:", binario[4])
            print("RST:", binario[5])
            print("SYN:", binario[6])
            print("FIN:", binario[7])
            lista_IP.remove(lista_IP[0])
            temp = lista_IP[0] + lista_IP[1] 
            print("Tamano de ventana:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 2)
            print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
            funct.deleteElements(lista_IP, 2)
            if binario[2] == "1":
                temp = lista_IP[0] + lista_IP[1]
                print("Puntero urgente:", (int(temp, 16)))
            else:
                pass
            funct.deleteElements(lista_IP, 2)
        elif protocolo_actual == "UDP":
            print("\tUDP")
            print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
            funct.deleteElements(lista_IP, 2)
            temp = lista_IP[0] + lista_IP[1] 
            print("Longitud total:", (int(temp, 16)))
            funct.deleteElements(lista_IP, 2)  
            print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
            funct.deleteElements(lista_IP,2)
        print(funct.imprimirDatos(lista_IP, name="Data"))
        # print(lista_IP)