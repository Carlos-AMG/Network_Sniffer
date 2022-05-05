from curses import raw
import socket
import funciones as funct

def main(lista_datos):

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
    # with open("Files/ethernet_ipv4_udp_dns_1.bin", mode="rb") as file:
    content = raw_data[0]
    for _bytes in content:
        lista_datos.append(hex(_bytes)[2:].zfill(2))
    # lista_datos.reverse()
    lista_IP = lista_datos[14:]
    lista_original = lista_datos[:]
    print("\tEthernet")
    print(funct.imprimirDatos(lista_datos, name="Target"))
    print(funct.imprimirDatos(lista_datos, name="Source"))
    print(funct.imprimirDatos(lista_datos, name="Type"), dict_type[f'{lista_datos[12]}:{lista_datos[13]}'])
    #print(funct.imprimirDatos(lista_datos, name="Data"))
    try:
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
                auxiliar_portv1 = int(lista_IP[0] + lista_IP[1], 16)
                funct.deleteElements(lista_IP, 2)
                print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv2 = int(lista_IP[0] + lista_IP[1], 16)
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
                if auxiliar_portv1 == 53 or auxiliar_portv2 == 53:
                    temp = funct.DNS(lista_IP, lista_original)
            elif protocolo_actual == "UDP":
                print("\tUDP")
                # print(funct.imprimirDatos(lista_IP, name="Data"))
                print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv1 = int(lista_IP[0] + lista_IP[1], 16)
                # print("This is the auxiliar port 1:", auxiliar_portv1)
                funct.deleteElements(lista_IP, 2)
                print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv2 = int(lista_IP[0] + lista_IP[1], 16)
                # print("This is the auxiliar port 2:", auxiliar_portv2)
                funct.deleteElements(lista_IP, 2)
                temp = lista_IP[0] + lista_IP[1] 
                print("Longitud total:", (int(temp, 16)))
                funct.deleteElements(lista_IP, 2)
                print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
                funct.deleteElements(lista_IP,2)
                if auxiliar_portv1 == 53 or auxiliar_portv2 == 53:
                    temp = funct.DNS(lista_IP, lista_original)
                #     print("\tDNS")
            # print(funct.imprimirDatos(lista_copia, name="Data"))
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
            print("Etiqueta de flujo: " + str(int(lista_IP[1][1] + lista_IP[2] + lista_IP[3], 16)))#hacer funcion en caso de necesitar convertir bin a decimal
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
                auxiliar_portv1 = int(lista_IP[0] + lista_IP[1], 16)
                funct.deleteElements(lista_IP, 2)
                print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv2 = int(lista_IP[0] + lista_IP[1], 16)
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
                if auxiliar_portv1 == 53 or auxiliar_portv2 == 53:
                    temp = funct.DNS(lista_IP, lista_original)
            elif protocolo_actual == "UDP":
                print("\tUDP")
                print("Puerto de origen:" , funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv1 = int(lista_IP[0] + lista_IP[1], 16)
                funct.deleteElements(lista_IP, 2)
                print("Puerto de destino:",funct.puertos(lista_IP[0] + lista_IP[1]))
                auxiliar_portv2 = int(lista_IP[0] + lista_IP[1], 16)
                funct.deleteElements(lista_IP, 2)
                temp = lista_IP[0] + lista_IP[1] 
                print("Longitud total:", (int(temp, 16)))
                funct.deleteElements(lista_IP, 2)  
                print("Checksum: " + lista_IP[0] + ":" + lista_IP[1])
                funct.deleteElements(lista_IP,2)
                if auxiliar_portv1 == 53 or auxiliar_portv2 == 53:
                    temp = funct.DNS(lista_IP, lista_original)
            # print(funct.imprimirDatos(lista_IP, name="Data"))
            # print(lista_IP)
    except KeyError:
        print("No tenemos tal protocolo")

if __name__ == "__main__":
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
    for x in range(0,10):
        raw_data = s.recvfrom(65565)
        lista_datos = []
        for _bytes in raw_data[0]:
            lista_datos.append(hex(_bytes)[2:].zfill(2))
        main(lista_datos)