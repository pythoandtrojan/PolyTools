#!/usr/bin/env python3
import requests
import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

# Cores
VERDE = Fore.GREEN
VERMELHO = Fore.RED
AMARELO = Fore.YELLOW
AZUL = Fore.BLUE
MAGENTA = Fore.MAGENTA
CIANO = Fore.CYAN
BRANCO = Fore.WHITE
NEGRITO = Style.BRIGHT
RESET = Style.RESET_ALL

class BuscadorDD:
    def __init__(self):
        self.ddd_brasil = {
            '11': {
                'estado': 'SP',
                'cidades': [
                    'São Paulo (Capital)',
                    'Guarulhos',
                    'São Bernardo do Campo',
                    'Santo André',
                    'Osasco',
                    'Mogi das Cruzes',
                    'Diadema',
                    'Itaquaquecetuba',
                    'São José dos Campos',
                    'Barueri'
                ]
            },
            '12': {
                'estado': 'SP', 
                'cidades': [
                    'São José dos Campos',
                    'Jacareí',
                    'Taubaté',
                    'Caçapava',
                    'Caraguatatuba',
                    'Ubatuba',
                    'Pindamonhangaba',
                    'Guaratinguetá',
                    'Lorena',
                    'Cruzeiro'
                ]
            },
            '13': {
                'estado': 'SP',
                'cidades': [
                    'Santos',
                    'São Vicente',
                    'Guarujá',
                    'Praia Grande',
                    'Cubatão',
                    'Itanhaém',
                    'Peruíbe',
                    'Mongaguá',
                    'Bertióga',
                    'São Sebastião'
                ]
            },
            '14': {
                'estado': 'SP',
                'cidades': [
                    'Bauru',
                    'Jaú',
                    'Botucatu',
                    'Avaré',
                    'Lins',
                    'Marília',
                    'Ourinhos',
                    'Lençóis Paulista',
                    'Piraju',
                    'Igaraçu do Tietê'
                ]
            },
            '15': {
                'estado': 'SP',
                'cidades': [
                    'Sorocaba',
                    'Itapetininga',
                    'Itu',
                    'Tatuí',
                    'Porto Feliz',
                    'Boituva',
                    'Salto',
                    'Capão Bonito',
                    'Araçoiaba da Serra',
                    'Iperó'
                ]
            },
            '16': {
                'estado': 'SP',
                'cidades': [
                    'Ribeirão Preto',
                    'São Carlos',
                    'Araraquara',
                    'Franca',
                    'Batatais',
                    'Sertãozinho',
                    'Barretos',
                    'Jaboticabal',
                    'Matão',
                    'Taquaritinga'
                ]
            },
            '17': {
                'estado': 'SP',
                'cidades': [
                    'São José do Rio Preto',
                    'Catanduva',
                    'Votuporanga',
                    'Barretos',
                    'Jales',
                    'Fernandópolis',
                    'Santa Fé do Sul',
                    'Mirassol',
                    'Tanabi',
                    'Novo Horizonte'
                ]
            },
            '18': {
                'estado': 'SP',
                'cidades': [
                    'Presidente Prudente',
                    'Araçatuba',
                    'Assis',
                    'Dracena',
                    'Adamantina',
                    'Tupã',
                    'Birigui',
                    'Penápolis',
                    'Presidente Epitácio',
                    'Presidente Venceslau'
                ]
            },
            '19': {
                'estado': 'SP',
                'cidades': [
                    'Campinas',
                    'Piracicaba',
                    'Limeira',
                    'Americana',
                    'Santa Bárbara dOeste',
                    'Rio Claro',
                    'Paulínia',
                    'Hortolândia',
                    'Sumaré',
                    'Indaiatuba'
                ]
            },
            '21': {
                'estado': 'RJ',
                'cidades': [
                    'Rio de Janeiro (Capital)',
                    'Duque de Caxias',
                    'São Gonçalo',
                    'Niterói',
                    'Nova Iguaçu',
                    'Belford Roxo',
                    'São João de Meriti',
                    'Petrópolis',
                    'Magé',
                    'Itaboraí'
                ]
            },
            '22': {
                'estado': 'RJ',
                'cidades': [
                    'Campos dos Goytacazes',
                    'Cabo Frio',
                    'Macaé',
                    'Nova Friburgo',
                    'Teresópolis',
                    'Araruama',
                    'Arraial do Cabo',
                    'Rio das Ostras',
                    'Saquarema',
                    'Búzios'
                ]
            },
            '24': {
                'estado': 'RJ',
                'cidades': [
                    'Volta Redonda',
                    'Barra Mansa',
                    'Angra dos Reis',
                    'Resende',
                    'Petrópolis',
                    'Itaguaí',
                    'Paracambi',
                    'Seropédica',
                    'Mendes',
                    'Pinheiral'
                ]
            },
            '27': {
                'estado': 'ES',
                'cidades': [
                    'Vitória (Capital)',
                    'Vila Velha',
                    'Serra',
                    'Cariacica',
                    'Guarapari',
                    'Linhares',
                    'Aracruz',
                    'Fundão',
                    'Viana',
                    'Santa Maria de Jetibá'
                ]
            },
            '28': {
                'estado': 'ES',
                'cidades': [
                    'Cachoeiro de Itapemirim',
                    'Alegre',
                    'Muqui',
                    'Marataízes',
                    'Itapemirim',
                    'Castelo',
                    'Vargem Alta',
                    'Atílio Vivácqua',
                    'Iúna',
                    'Irupi'
                ]
            },
            '31': {
                'estado': 'MG',
                'cidades': [
                    'Belo Horizonte (Capital)',
                    'Contagem',
                    'Betim',
                    'Ribeirão das Neves',
                    'Santa Luzia',
                    'Ibirité',
                    'Sabará',
                    'Nova Lima',
                    'Caeté',
                    'Brumadinho'
                ]
            },
            '32': {
                'estado': 'MG',
                'cidades': [
                    'Juiz de Fora',
                    'Cataguases',
                    'Ubá',
                    'São João Nepomuceno',
                    'Muriae',
                    'Leopoldina',
                    'Astolfo Dutra',
                    'Rio Pomba',
                    'Visconde do Rio Branco',
                    'Além Paraíba'
                ]
            },
            '33': {
                'estado': 'MG',
                'cidades': [
                    'Governador Valadares',
                    'Teófilo Otoni',
                    'Caratinga',
                    'Manhuaçu',
                    'Aimorés',
                    'Mantena',
                    'Itambacuri',
                    'Santa Maria do Suaçuí',
                    'Engenheiro Caldas',
                    'Tarumirim'
                ]
            },
            '34': {
                'estado': 'MG',
                'cidades': [
                    'Uberlândia',
                    'Uberaba',
                    'Araguari',
                    'Ituiutaba',
                    'Patos de Minas',
                    'Patrocínio',
                    'Monte Carmelo',
                    'Araxá',
                    'Tupaciguara',
                    'Prata'
                ]
            },
            '35': {
                'estado': 'MG',
                'cidades': [
                    'Poços de Caldas',
                    'Pouso Alegre',
                    'Varginha',
                    'Itajubá',
                    'Guaxupé',
                    'Alfenas',
                    'Três Corações',
                    'São Lourenço',
                    'São Sebastião do Paraíso',
                    'Campanha'
                ]
            },
            '37': {
                'estado': 'MG',
                'cidades': [
                    'Divinópolis',
                    'Itaúna',
                    'Pará de Minas',
                    'Formiga',
                    'Oliveira',
                    'Carmo do Cajuru',
                    'Cláudio',
                    'Itapecerica',
                    'Nova Serrana',
                    'Santo Antônio do Monte'
                ]
            },
            '38': {
                'estado': 'MG',
                'cidades': [
                    'Montes Claros',
                    'Pirapora',
                    'Janaúba',
                    'Januária',
                    'Bocaiúva',
                    'Espinosa',
                    'Salinas',
                    'São Francisco',
                    'Coração de Jesus',
                    'Grão Mogol'
                ]
            },
            '41': {
                'estado': 'PR',
                'cidades': [
                    'Curitiba (Capital)',
                    'São José dos Pinhais',
                    'Araucária',
                    'Pinhais',
                    'Colombo',
                    'Almirante Tamandaré',
                    'Campo Largo',
                    'Fazenda Rio Grande',
                    'Campo Magro',
                    'Balsa Nova'
                ]
            },
            '42': {
                'estado': 'PR',
                'cidades': [
                    'Ponta Grossa',
                    'Guarapuava',
                    'Castro',
                    'Palmeira',
                    'Carambeí',
                    'Irati',
                    'Prudentópolis',
                    'Telêmaco Borba',
                    'Imbituva',
                    'Ivaí'
                ]
            },
            '43': {
                'estado': 'PR',
                'cidades': [
                    'Londrina',
                    'Arapongas',
                    'Apucarana',
                    'Cambé',
                    'Rolândia',
                    'Jandaia do Sul',
                    'Ibiporã',
                    'Sertanópolis',
                    'Bela Vista do Paraíso',
                    'Tamarana'
                ]
            },
            '44': {
                'estado': 'PR',
                'cidades': [
                    'Maringá',
                    'Cianorte',
                    'Umuarama',
                    'Paranavaí',
                    'Campo Mourão',
                    'Sarandi',
                    'Cidade Gaúcha',
                    'Terra Boa',
                    'Astorga',
                    'Doutor Camargo'
                ]
            },
            '45': {
                'estado': 'PR',
                'cidades': [
                    'Foz do Iguaçu',
                    'Cascavel',
                    'Toledo',
                    'Medianeira',
                    'Santa Terezinha de Itaipu',
                    'São Miguel do Iguaçu',
                    'Matelândia',
                    'Missal',
                    'Ramilândia',
                    'Serranópolis do Iguaçu'
                ]
            },
            '46': {
                'estado': 'PR',
                'cidades': [
                    'Francisco Beltrão',
                    'Pato Branco',
                    'Marmeleiro',
                    'Enéas Marques',
                    'Verê',
                    'Coronel Vivida',
                    'Chopinzinho',
                    'Mangueirinha',
                    'Quedas do Iguaçu',
                    'Sulina'
                ]
            },
            '47': {
                'estado': 'SC',
                'cidades': [
                    'Joinville',
                    'Blumenau',
                    'Jaraguá do Sul',
                    'São Bento do Sul',
                    'Mafra',
                    'Rio Negrinho',
                    'Guaramirim',
                    'Schroeder',
                    'Corupá',
                    'Barra Velha'
                ]
            },
            '48': {
                'estado': 'SC',
                'cidades': [
                    'Florianópolis (Capital)',
                    'São José',
                    'Palhoça',
                    'Biguaçu',
                    'Santo Amaro da Imperatriz',
                    'Águas Mornas',
                    'Governador Celso Ramos',
                    'Antônio Carlos',
                    'Paulo Lopes',
                    'São Pedro de Alcântara'
                ]
            },
            '49': {
                'estado': 'SC',
                'cidades': [
                    'Chapecó',
                    'Xanxerê',
                    'Concórdia',
                    'São Miguel do Oeste',
                    'Maravilha',
                    'Pinhalzinho',
                    'Seara',
                    'Quilombo',
                    'Caxambu do Sul',
                    'Guatambú'
                ]
            },
            '51': {
                'estado': 'RS',
                'cidades': [
                    'Porto Alegre (Capital)',
                    'Canoas',
                    'Gravataí',
                    'Viamão',
                    'Novo Hamburgo',
                    'São Leopoldo',
                    'Alvorada',
                    'Cachoeirinha',
                    'Guaíba',
                    'Eldorado do Sul'
                ]
            },
            '53': {
                'estado': 'RS',
                'cidades': [
                    'Pelotas',
                    'Rio Grande',
                    'Bagé',
                    'Santa Vitória do Palmar',
                    'Jaguarão',
                    'Canguçu',
                    'Capão do Leão',
                    'Cerrito',
                    'Pedro Osório',
                    'Morro Redondo'
                ]
            },
            '54': {
                'estado': 'RS',
                'cidades': [
                    'Caxias do Sul',
                    'Bento Gonçalves',
                    'Farroupilha',
                    'Garibaldi',
                    'Carlos Barbosa',
                    'Nova Prata',
                    'Flores da Cunha',
                    'Vacaria',
                    'Veranópolis',
                    'Antônio Prado'
                ]
            },
            '55': {
                'estado': 'RS',
                'cidades': [
                    'Santa Maria',
                    'Uruguaiana',
                    'Santana do Livramento',
                    'São Gabriel',
                    'Rosário do Sul',
                    'São Vicente do Sul',
                    'Itaara',
                    'Júlio de Castilhos',
                    'Mata',
                    'Formigueiro'
                ]
            },
            '61': {
                'estado': 'DF',
                'cidades': [
                    'Brasília (Capital)',
                    'Ceilândia',
                    'Taguatinga',
                    'Samambaia',
                    'Planaltina',
                    'Sobradinho',
                    'Gama',
                    'Santa Maria',
                    'Paranoá',
                    'Recanto das Emas'
                ]
            },
            '62': {
                'estado': 'GO',
                'cidades': [
                    'Goiânia (Capital)',
                    'Aparecida de Goiânia',
                    'Anápolis',
                    'Rio Verde',
                    'Luziânia',
                    'Águas Lindas de Goiás',
                    'Valparaíso de Goiás',
                    'Trindade',
                    'Formosa',
                    'Novo Gama'
                ]
            },
            '63': {
                'estado': 'TO',
                'cidades': [
                    'Palmas (Capital)',
                    'Araguaína',
                    'Gurupi',
                    'Porto Nacional',
                    'Paraíso do Tocantins',
                    'Araguatins',
                    'Colinas do Tocantins',
                    'Guaraí',
                    'Tocantinópolis',
                    'Miracema do Tocantins'
                ]
            },
            '64': {
                'estado': 'GO',
                'cidades': [
                    'Rio Verde',
                    'Jataí',
                    'Itumbiara',
                    'Catalão',
                    'Caldas Novas',
                    'Quirinópolis',
                    'São Luís de Montes Belos',
                    'Mineiros',
                    'Morrinhos',
                    'Pires do Rio'
                ]
            },
            '65': {
                'estado': 'MT',
                'cidades': [
                    'Cuiabá (Capital)',
                    'Várzea Grande',
                    'Rondonópolis',
                    'Sinop',
                    'Tangará da Serra',
                    'Cáceres',
                    'Sorriso',
                    'Lucas do Rio Verde',
                    'Primavera do Leste',
                    'Barra do Garças'
                ]
            },
            '66': {
                'estado': 'MT',
                'cidades': [
                    'Rondonópolis',
                    'Sinop',
                    'Lucas do Rio Verde',
                    'Sorriso',
                    'Nova Mutum',
                    'Tangará da Serra',
                    'Campo Verde',
                    'Diamantino',
                    'Jaciara',
                    'Campo Novo do Parecis'
                ]
            },
            '67': {
                'estado': 'MS',
                'cidades': [
                    'Campo Grande (Capital)',
                    'Dourados',
                    'Corumbá',
                    'Três Lagoas',
                    'Ponta Porã',
                    'Naviraí',
                    'Nova Andradina',
                    'Aquidauana',
                    'Sidrolândia',
                    'Paranaíba'
                ]
            },
            '68': {
                'estado': 'AC',
                'cidades': [
                    'Rio Branco (Capital)',
                    'Cruzeiro do Sul',
                    'Sena Madureira',
                    'Tarauacá',
                    'Feijó',
                    'Brasiléia',
                    'Xapuri',
                    'Plácido de Castro',
                    'Mâncio Lima',
                    'Epitaciolândia'
                ]
            },
            '69': {
                'estado': 'RO',
                'cidades': [
                    'Porto Velho (Capital)',
                    'Ji-Paraná',
                    'Ariquemes',
                    'Vilhena',
                    'Cacoal',
                    'Rolim de Moura',
                    'Jaru',
                    'Guajará-Mirim',
                    'Ouro Preto do Oeste',
                    'Pimenta Bueno'
                ]
            },
            '71': {
                'estado': 'BA',
                'cidades': [
                    'Salvador (Capital)',
                    'Feira de Santana',
                    'Camaçari',
                    'Vitória da Conquista',
                    'Itabuna',
                    'Juazeiro',
                    'Ilhéus',
                    'Lauro de Freitas',
                    'Jequié',
                    'Alagoinhas'
                ]
            },
            '73': {
                'estado': 'BA',
                'cidades': [
                    'Ilhéus',
                    'Itabuna',
                    'Porto Seguro',
                    'Eunápolis',
                    'Teixeira de Freitas',
                    'Barreiras',
                    'Paulo Afonso',
                    'Bom Jesus da Lapa',
                    'Valença',
                    'Candeias'
                ]
            },
            '74': {
                'estado': 'BA',
                'cidades': [
                    'Juazeiro',
                    'Paulo Afonso',
                    'Barreiras',
                    'Bom Jesus da Lapa',
                    'Irecê',
                    'Jacobina',
                    'Senhor do Bonfim',
                    'Xique-Xique',
                    'Casa Nova',
                    'Remanso'
                ]
            },
            '75': {
                'estado': 'BA',
                'cidades': [
                    'Feira de Santana',
                    'Alagoinhas',
                    'Santo Antônio de Jesus',
                    'Catu',
                    'Conceição do Coité',
                    'Serrinha',
                    'Valença',
                    'Cruz das Almas',
                    'Entre Rios',
                    'Amélia Rodrigues'
                ]
            },
            '77': {
                'estado': 'BA',
                'cidades': [
                    'Barreiras',
                    'Luís Eduardo Magalhães',
                    'Santa Maria da Vitória',
                    'Bom Jesus da Lapa',
                    'Ibotirama',
                    'Correntina',
                    'Cristópolis',
                    'Formosa do Rio Preto',
                    'Riachão das Neves',
                    'São Desidério'
                ]
            },
            '79': {
                'estado': 'SE',
                'cidades': [
                    'Aracaju (Capital)',
                    'Nossa Senhora do Socorro',
                    'Lagarto',
                    'Itabaiana',
                    'São Cristóvão',
                    'Estância',
                    'Tobias Barreto',
                    'Simão Dias',
                    'Poço Redondo',
                    'Capela'
                ]
            },
            '81': {
                'estado': 'PE',
                'cidades': [
                    'Recife (Capital)',
                    'Jaboatão dos Guararapes',
                    'Olinda',
                    'Caruaru',
                    'Petrolina',
                    'Paulista',
                    'Cabo de Santo Agostinho',
                    'Camaragibe',
                    'Garanhuns',
                    'Vitória de Santo Antão'
                ]
            },
            '82': {
                'estado': 'AL',
                'cidades': [
                    'Maceió (Capital)',
                    'Arapiraca',
                    'Rio Largo',
                    'Palmeira dos Índios',
                    'União dos Palmares',
                    'São Miguel dos Campos',
                    'Penedo',
                    'Coruripe',
                    'Campo Alegre',
                    'Santana do Ipanema'
                ]
            },
            '83': {
                'estado': 'PB',
                'cidades': [
                    'João Pessoa (Capital)',
                    'Campina Grande',
                    'Santa Rita',
                    'Patos',
                    'Bayeux',
                    'Sousa',
                    'Cajazeiras',
                    'Guarabira',
                    'Cabedelo',
                    'Sapé'
                ]
            },
            '84': {
                'estado': 'RN',
                'cidades': [
                    'Natal (Capital)',
                    'Mossoró',
                    'Parnamirim',
                    'São Gonçalo do Amarante',
                    'Macaíba',
                    'Ceará-Mirim',
                    'Caicó',
                    'Açu',
                    'Currais Novos',
                    'São José de Mipibu'
                ]
            },
            '85': {
                'estado': 'CE',
                'cidades': [
                    'Fortaleza (Capital)',
                    'Caucaia',
                    'Maracanaú',
                    'Maranguape',
                    'Sobral',
                    'Juazeiro do Norte',
                    'Crato',
                    'Itapipoca',
                    'Pacatuba',
                    'Quixadá'
                ]
            },
            '86': {
                'estado': 'PI',
                'cidades': [
                    'Teresina (Capital)',
                    'Parnaíba',
                    'Picos',
                    'Floriano',
                    'Barras',
                    'Campo Maior',
                    'Piripiri',
                    'Altos',
                    'Pedro II',
                    'José de Freitas'
                ]
            },
            '87': {
                'estado': 'PE',
                'cidades': [
                    'Petrolina',
                    'Salgueiro',
                    'Serra Talhada',
                    'Arcoverde',
                    'Ouricuri',
                    'Bom Conselho',
                    'Bodocó',
                    'Araripina',
                    'Trindade',
                    'Custódia'
                ]
            },
            '88': {
                'estado': 'CE',
                'cidades': [
                    'Juazeiro do Norte',
                    'Crato',
                    'Barbalha',
                    'Sobral',
                    'Iguatu',
                    'Crateús',
                    'Russas',
                    'Quixadá',
                    'Aracati',
                    'Canindé'
                ]
            },
            '89': {
                'estado': 'PI',
                'cidades': [
                    'Picos',
                    'Oeiras',
                    'São Raimundo Nonato',
                    'Corrente',
                    'Paulistana',
                    'Jaicós',
                    'Simões',
                    'Alegrete do Piauí',
                    'Padre Marcos',
                    'Francisco Santos'
                ]
            },
            '91': {
                'estado': 'PA',
                'cidades': [
                    'Belém (Capital)',
                    'Ananindeua',
                    'Santarém',
                    'Marabá',
                    'Castanhal',
                    'Paragominas',
                    'Abaetetuba',
                    'Cametá',
                    'Bragança',
                    'Barcarena'
                ]
            },
            '92': {
                'estado': 'AM',
                'cidades': [
                    'Manaus (Capital)',
                    'Parintins',
                    'Itacoatiara',
                    'Manacapuru',
                    'Coari',
                    'Tefé',
                    'Maués',
                    'Humaitá',
                    'Iranduba',
                    'Borba'
                ]
            },
            '93': {
                'estado': 'PA',
                'cidades': [
                    'Santarém',
                    'Altamira',
                    'Itaituba',
                    'Oriximiná',
                    'Alenquer',
                    'Monte Alegre',
                    'Prainha',
                    'Juruti',
                    'Óbidos',
                    'Faro'
                ]
            },
            '94': {
                'estado': 'PA',
                'cidades': [
                    'Marabá',
                    'Parauapebas',
                    'São Félix do Xingu',
                    'Tucuruí',
                    'Redenção',
                    'Xinguara',
                    'Conceição do Araguaia',
                    'Jacundá',
                    'Curionópolis',
                    'Eldorado dos Carajás'
                ]
            },
            '95': {
                'estado': 'RR',
                'cidades': [
                    'Boa Vista (Capital)',
                    'Rorainópolis',
                    'Caracaraí',
                    'Alto Alegre',
                    'Mucajaí',
                    'Cantá',
                    'Bonfim',
                    'Normandia',
                    'Uiramutã',
                    'Caroebe'
                ]
            },
            '96': {
                'estado': 'AP',
                'cidades': [
                    'Macapá (Capital)',
                    'Santana',
                    'Laranjal do Jari',
                    'Oiapoque',
                    'Porto Grande',
                    'Mazagão',
                    'Tartarugalzinho',
                    'Vitória do Jari',
                    'Pedra Branca do Amapari',
                    'Calçoene'
                ]
            },
            '97': {
                'estado': 'AM',
                'cidades': [
                    'Manaus (Capital)',
                    'Coari',
                    'Tefé',
                    'Eirunepé',
                    'Carauari',
                    'Boca do Acre',
                    'Lábrea',
                    'São Gabriel da Cachoeira',
                    'Maués',
                    'Barreirinha'
                ]
            },
            '98': {
                'estado': 'MA',
                'cidades': [
                    'São Luís (Capital)',
                    'Imperatriz',
                    'São José de Ribamar',
                    'Timon',
                    'Caxias',
                    'Codó',
                    'Paço do Lumiar',
                    'Açailândia',
                    'Bacabal',
                    'Santa Inês'
                ]
            },
            '99': {
                'estado': 'MA',
                'cidades': [
                    'Imperatriz',
                    'Açailândia',
                    'Santa Inês',
                    'Bacabal',
                    'Balsas',
                    'Chapadinha',
                    'Barra do Corda',
                    'Pinheiro',
                    'Codó',
                    'Coelho Neto'
                ]
            }
        }
        
        # DDI mantido igual
        self.ddi_paises = {
            '1': 'Estados Unidos/Canadá',
            '7': 'Rússia/Cazaquistão',
            '20': 'Egito',
            '27': 'África do Sul',
            '30': 'Grécia',
            '31': 'Países Baixos',
            '32': 'Bélgica',
            '33': 'França',
            '34': 'Espanha',
            '36': 'Hungria',
            '39': 'Itália',
            '40': 'Romênia',
            '41': 'Suíça',
            '43': 'Áustria',
            '44': 'Reino Unido',
            '45': 'Dinamarca',
            '46': 'Suécia',
            '47': 'Noruega',
            '48': 'Polônia',
            '49': 'Alemanha',
            '51': 'Peru',
            '52': 'México',
            '53': 'Cuba',
            '54': 'Argentina',
            '55': 'Brasil',
            '56': 'Chile',
            '57': 'Colômbia',
            '58': 'Venezuela',
            '60': 'Malásia',
            '61': 'Austrália',
            '62': 'Indonésia',
            '63': 'Filipinas',
            '64': 'Nova Zelândia',
            '65': 'Singapura',
            '66': 'Tailândia',
            '81': 'Japão',
            '82': 'Coreia do Sul',
            '84': 'Vietnã',
            '86': 'China',
            '90': 'Turquia',
            '91': 'Índia',
            '92': 'Paquistão',
            '93': 'Afeganistão',
            '94': 'Sri Lanka',
            '95': 'Myanmar',
            '98': 'Irã',
            '212': 'Marrocos',
            '213': 'Argélia',
            '216': 'Tunísia',
            '218': 'Líbia',
            '220': 'Gâmbia',
            '221': 'Senegal',
            '222': 'Mauritânia',
            '223': 'Mali',
            '224': 'Guiné',
            '225': 'Costa do Marfim',
            '226': 'Burkina Faso',
            '227': 'Níger',
            '228': 'Togo',
            '229': 'Benin',
            '230': 'Maurício',
            '231': 'Libéria',
            '232': 'Serra Leoa',
            '233': 'Gana',
            '234': 'Nigéria',
            '235': 'Chade',
            '236': 'República Centro-Africana',
            '237': 'Camarões',
            '238': 'Cabo Verde',
            '239': 'São Tomé e Príncipe',
            '240': 'Guiné Equatorial',
            '241': 'Gabão',
            '242': 'República do Congo',
            '243': 'República Democrática do Congo',
            '244': 'Angola',
            '245': 'Guiné-Bissau',
            '246': 'Diego Garcia',
            '248': 'Seicheles',
            '249': 'Sudão',
            '250': 'Ruanda',
            '251': 'Etiópia',
            '252': 'Somália',
            '253': 'Djibuti',
            '254': 'Quênia',
            '255': 'Tanzânia',
            '256': 'Uganda',
            '257': 'Burundi',
            '258': 'Moçambique',
            '260': 'Zâmbia',
            '261': 'Madagáscar',
            '262': 'Reunião',
            '263': 'Zimbábue',
            '264': 'Namíbia',
            '265': 'Malawi',
            '266': 'Lesoto',
            '267': 'Botsuana',
            '268': 'Essuatíni',
            '269': 'Comores',
            '290': 'Santa Helena',
            '291': 'Eritreia',
            '297': 'Aruba',
            '298': 'Ilhas Feroe',
            '299': 'Groenlândia'
        }

    def buscar_ddd(self, ddd: str) -> dict:
        """Busca informações do DDD"""
        ddd = ddd.strip()
        resultado = {
            'ddd': ddd,
            'encontrado': False,
            'estado': 'Não encontrado',
            'cidades': [],
            'total_cidades': 0,
            'pais': 'Brasil',
            'codigo_pais': '55'
        }
        
        if ddd in self.ddd_brasil:
            dados = self.ddd_brasil[ddd]
            resultado.update({
                'encontrado': True,
                'estado': dados['estado'],
                'cidades': dados['cidades'],
                'total_cidades': len(dados['cidades']),
                'regiao': self._identificar_regiao(ddd)
            })
        
        return resultado

    def buscar_ddi(self, ddi: str) -> dict:
        """Busca informações do DDI"""
        ddi = ddi.strip()
        resultado = {
            'ddi': ddi,
            'encontrado': False,
            'pais': 'Não encontrado',
            'continente': 'Desconhecido'
        }
        
        if ddi in self.ddi_paises:
            pais = self.ddi_paises[ddi]
            resultado.update({
                'encontrado': True,
                'pais': pais,
                'continente': self._identificar_continente(pais)
            })
        else:
            for code, pais in self.ddi_paises.items():
                if ddi.startswith(code):
                    resultado.update({
                        'encontrado': True,
                        'pais': pais,
                        'continente': self._identificar_continente(pais),
                        'observacao': f'DDI pode ser {code} (correspondência parcial)'
                    })
                    break
        
        return resultado

    def _identificar_regiao(self, ddd: str) -> str:
        """Identifica a região do DDD"""
        regioes = {
            '11-19': 'Sudeste (SP)',
            '21-24': 'Sudeste (RJ/ES)',
            '27-28': 'Sudeste (ES)',
            '31-38': 'Sudeste (MG)',
            '41-46': 'Sul (PR)',
            '47-49': 'Sul (SC)',
            '51-55': 'Sul (RS)',
            '61': 'Centro-Oeste (DF)',
            '62-64': 'Centro-Oeste (GO)',
            '65-66': 'Centro-Oeste (MT)',
            '67': 'Centro-Oeste (MS)',
            '68-69': 'Norte (AC/RO)',
            '71-77': 'Nordeste (BA)',
            '79': 'Nordeste (SE)',
            '81-89': 'Nordeste (PE/AL/PB/RN/CE/PI)',
            '91-99': 'Norte (PA/AM/RR/AP/MA)'
        }
        
        ddd_num = int(ddd)
        for intervalo, regiao in regioes.items():
            inicio, fim = map(int, intervalo.split('-')) if '-' in intervalo else (int(intervalo), int(intervalo))
            if inicio <= ddd_num <= fim:
                return regiao
        return 'Região não identificada'

    def _identificar_continente(self, pais: str) -> str:
        """Identifica o continente do país"""
        america = ['Brasil', 'Estados Unidos', 'Canadá', 'México', 'Argentina', 'Chile', 'Colômbia', 'Peru', 'Venezuela', 'Cuba']
        europa = ['Reino Unido', 'França', 'Alemanha', 'Itália', 'Espanha', 'Portugal', 'Países Baixos', 'Bélgica', 'Suíça', 'Áustria']
        asia = ['China', 'Japão', 'Índia', 'Coreia do Sul', 'Rússia', 'Tailândia', 'Filipinas', 'Vietnã', 'Singapura', 'Malásia']
        africa = ['África do Sul', 'Egito', 'Nigéria', 'Quênia', 'Marrocos', 'Argélia', 'Angola', 'Moçambique']
        oceania = ['Austrália', 'Nova Zelândia']
        
        if pais in america:
            return 'América'
        elif pais in europa:
            return 'Europa'
        elif pais in asia:
            return 'Ásia'
        elif pais in africa:
            return 'África'
        elif pais in oceania:
            return 'Oceania'
        else:
            return 'Desconhecido'

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"""
{VERDE}{NEGRITO}
██████╗ ██████╗ ██████╗         ██╗    ██████╗ ██████╗ ██╗
██╔══██╗██╔══██╗██╔══██╗       ██╔╝    ██╔══██╗██╔══██╗██║
██║  ██║██║  ██║██║  ██║      ██╔╝     ██║  ██║██║  ██║██║
██║  ██║██║  ██║██║  ██║     ██╔╝      ██║  ██║██║  ██║██║
██████╔╝██████╔╝██████╔╝    ██╔╝       ██████╔╝██████╔╝██║
╚═════╝ ╚═════╝ ╚═════╝     ╚═╝        ╚═════╝ ╚═════╝ ╚═╝
                                                          
{RESET}
{CIANO}{NEGRITO}   BUSCADOR DDD/DDI v3.0
   Terminal de Códigos Telefônicos
{RESET}
{AMARELO}   DDD: Códigos de área brasileiros
   DDI: Códigos internacionais
{RESET}""")

def mostrar_resultado_ddd(resultado: dict):
    """Exibe resultado da busca por DDD"""
    print(f"\n{CIANO}{NEGRITO}=== INFORMAÇÕES DDD ==={RESET}")
    print(f"{AZUL}DDD:{RESET} {resultado['ddd']}")
    
    if resultado['encontrado']:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ ENCONTRADO{RESET}")
        print(f"{AZUL}Estado:{RESET} {VERDE}{resultado['estado']}{RESET}")
        print(f"{AZUL}Região:{RESET} {CIANO}{resultado['regiao']}{RESET}")
        print(f"{AZUL}País:{RESET} {AMARELO}{resultado['pais']}{RESET}")
        print(f"{AZUL}Código País:{RESET} +{resultado['codigo_pais']}")
        
        print(f"\n{AZUL}Principais Cidades ({resultado['total_cidades']} listadas):{RESET}")
        for i, cidade in enumerate(resultado['cidades'], 1):
            print(f"  {VERDE}{i:2d}.{RESET} {cidade}")
            
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ NÃO ENCONTRADO{RESET}")
        print(f"{AZUL}Observação:{RESET} {VERMELHO}DDD brasileiro não cadastrado{RESET}")

def mostrar_resultado_ddi(resultado: dict):
    """Exibe resultado da busca por DDI"""
    print(f"\n{CIANO}{NEGRITO}=== INFORMAÇÕES DDI ==={RESET}")
    print(f"{AZUL}DDI:{RESET} +{resultado['ddi']}")
    
    if resultado['encontrado']:
        print(f"{AZUL}Status:{RESET} {VERDE}✓ ENCONTRADO{RESET}")
        print(f"{AZUL}País:{RESET} {VERDE}{resultado['pais']}{RESET}")
        print(f"{AZUL}Continente:{RESET} {CIANO}{resultado['continente']}{RESET}")
        if 'observacao' in resultado:
            print(f"{AZUL}Observação:{RESET} {AMARELO}{resultado['observacao']}{RESET}")
    else:
        print(f"{AZUL}Status:{RESET} {VERMELHO}✗ NÃO ENCONTRADO{RESET}")
        print(f"{AZUL}Sugestão:{RESET} {AMARELO}Verifique se o código está correto{RESET}")

def salvar_resultado(tipo: str, codigo: str, resultado: dict):
    """Salva resultado em arquivo JSON"""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{tipo}_{codigo}_{timestamp}.json"
    
    dados_salvar = {
        'tipo': tipo,
        'codigo': codigo,
        'data_consulta': datetime.now().isoformat(),
        'resultado': resultado
    }
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(dados_salvar, f, indent=2, ensure_ascii=False)
        print(f"{VERDE}[+] Resultado salvo em {filename}{RESET}")
        return True
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao salvar: {e}{RESET}")
        return False

def menu_principal():
    banner()
    print(f"\n{AMARELO}{NEGRITO}MENU PRINCIPAL - DDD/DDI{RESET}")
    print(f"{VERDE}[1]{RESET} Buscar DDD (Brasil)")
    print(f"{VERDE}[2]{RESET} Buscar DDI (Internacional)")
    print(f"{VERDE}[3]{RESET} Buscar Ambos")
    print(f"{VERDE}[4]{RESET} Listar Todos DDDs")
    print(f"{VERDE}[5]{RESET} Sobre")
    print(f"{VERDE}[6]{RESET} Sair")
    return input(f"\n{CIANO}Selecione uma opção: {RESET}")

def listar_todos_ddds():
    """Lista todos os DDDs brasileiros"""
    banner()
    print(f"\n{CIANO}{NEGRITO}=== TODOS OS DDDS BRASILEIROS ==={RESET}")
    
    buscador = BuscadorDD()
    ddds_ordenados = sorted(buscador.ddd_brasil.items(), key=lambda x: int(x[0]))
    
    print(f"\n{AZUL}Total de DDDs: {len(ddds_ordenados)}{RESET}\n")
    
    for i in range(0, len(ddds_ordenados), 3):
        linha = ""
        for j in range(3):
            if i + j < len(ddds_ordenados):
                ddd, dados = ddds_ordenados[i + j]
                linha += f"{VERDE}{ddd}: {AMARELO}{dados['estado']:<4}{RESET}  "
        print(linha)
    
    print(f"\n{CIANO}Use [1] para buscar informações detalhadas de um DDD específico{RESET}")

def buscar_ambos():
    """Busca DDD e DDI em sequência"""
    banner()
    print(f"\n{CIANO}{NEGRITO}=== BUSCA DDD + DDI ==={RESET}")
    
    buscador = BuscadorDD()
    
    # DDD
    ddd = input(f"\n{AMARELO}Digite o DDD (2 dígitos): {RESET}").strip()
    resultado_ddd = buscador.buscar_ddd(ddd)
    mostrar_resultado_ddd(resultado_ddd)
    
    # DDI
    ddi = input(f"\n{AMARELO}Digite o DDI (1-3 dígitos): {RESET}").strip()
    resultado_ddi = buscador.buscar_ddi(ddi)
    mostrar_resultado_ddi(resultado_ddi)
    
    # Salvar resultados
    salvar = input(f"\n{CIANO}Salvar resultados? (S/N): {RESET}").lower()
    if salvar in ['s', 'sim']:
        salvar_resultado('DDD', ddd, resultado_ddd)
        salvar_resultado('DDI', ddi, resultado_ddi)

def sobre():
    banner()
    print(f"""
{CIANO}{NEGRITO}SOBRE O BUSCADOR DDD/DDI{RESET}

{AMARELO}Funcionalidades:{RESET}
• Busca de DDDs brasileiros com localização
• Busca de DDIs internacionais por país
• Identificação de regiões e continentes
• Base de dados local completa

{AMARELO}DDD (Brasil):{RESET}
• Códigos de área telefônica brasileiros
• 2 dígitos (11-99)
• Identifica estado e principais cidades

{AMARELO}DDI (Internacional):{RESET}
• Códigos de discagem internacional
• 1-3 dígitos (+1 a +299)
• Identifica país e continente

{AMARELO}Exemplos:{RESET}
DDD: 11 (SP), 21 (RJ), 62 (GO), 71 (BA)
DDI: 1 (EUA/Canadá), 55 (Brasil), 44 (Reino Unido)

{VERDE}Pressione Enter para voltar...{RESET}""")
    input()

def main():
    try:
        buscador = BuscadorDD()
        
        while True:
            opcao = menu_principal()
            
            if opcao == '1':  # Buscar DDD
                banner()
                ddd = input(f"\n{CIANO}Digite o DDD (2 dígitos): {RESET}").strip()
                
                if not ddd.isdigit() or len(ddd) != 2:
                    print(f"{VERMELHO}[!] DDD deve conter 2 dígitos{RESET}")
                else:
                    resultado = buscador.buscar_ddd(ddd)
                    mostrar_resultado_ddd(resultado)
                    
                    salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                    if salvar in ['s', 'sim']:
                        salvar_resultado('DDD', ddd, resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '2':  # Buscar DDI
                banner()
                ddi = input(f"\n{CIANO}Digite o DDI (1-3 dígitos): {RESET}").strip()
                
                if not ddi.isdigit() or not 1 <= len(ddi) <= 3:
                    print(f"{VERMELHO}[!] DDI deve conter 1-3 dígitos{RESET}")
                else:
                    resultado = buscador.buscar_ddi(ddi)
                    mostrar_resultado_ddi(resultado)
                    
                    salvar = input(f"\n{CIANO}Salvar resultado? (S/N): {RESET}").lower()
                    if salvar in ['s', 'sim']:
                        salvar_resultado('DDI', ddi, resultado)
                
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '3':  # Buscar Ambos
                buscar_ambos()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '4':  # Listar DDDs
                listar_todos_ddds()
                input(f"\n{AMARELO}Pressione Enter para continuar...{RESET}")
            
            elif opcao == '5':  # Sobre
                sobre()
            
            elif opcao == '6':  # Sair
                print(f"\n{VERDE}[+] Saindo... Até logo!{RESET}")
                break
            
            else:
                print(f"{VERMELHO}[!] Opção inválida!{RESET}")
                input(f"{AMARELO}Pressione Enter para continuar...{RESET}")
    
    except KeyboardInterrupt:
        print(f"\n{VERMELHO}[!] Programa interrompido{RESET}")
        exit()

if __name__ == "__main__":
    main()
