import requests
from bs4 import BeautifulSoup
import json
from pwn import *

#We want to force GHDB to respond in json. Therefore we need these headers.
headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest'
    }

def performPreflight(preflightUrl):
    preflightResponse = requests.get(preflightUrl, headers=headers)
    if preflightResponse.status_code != 200:
        print("Preflight was not successful! Quitting!")
        exit(1)
    return preflightResponse.json()['recordsTotal']


def scrapeGHDB():
    ghdbRequestFormat = 'https://www.exploit-db.com/google-hacking-database?draw=3&columns[0][data]=date&columns[0][name]=date&columns[0][searchable]=true&columns[0][orderable]=true&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=url_title&columns[1][name]=url_title&columns[1][searchable]=true&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=cat_id&columns[2][name]=cat_id&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=author_id&columns[3][name]=author_id&columns[3][searchable]=false&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&order[0][column]=0&order[0][dir]=desc&start=120&length=10000&search[value]=&search[regex]=false&author=&category=&&draw=5&columns%5B0%5D%5Bdata%5D=date&columns%5B0%5D%5Bname%5D=date&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=url_title&columns%5B1%5D%5Bname%5D=url_title&columns%5B1%5D%5Bsearchable%5D=true&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=cat_id&columns%5B2%5D%5Bname%5D=cat_id&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=author_id&columns%5B3%5D%5Bname%5D=author_id&columns%5B3%5D%5Bsearchable%5D=false&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=desc&start={}&length=120&search%5Bvalue%5D=&search%5Bregex%5D=false&author=&category=&_=1646159037613'
    numberOfDorks = performPreflight(ghdbRequestFormat.format(str(0)))
    log.info("We currently have "+str(numberOfDorks)+" dorks")
    ghdbBase = 'https://www.exploit-db.com'
    i =0
    dorks = {}
    categories = []
    generalDorks =[]    
    #still possibly some off 
    while i < numberOfDorks:
        log.info("Fetching Dorks from "+str(i)+" to "+str(i+120))
        result = requests.get(ghdbRequestFormat.format(str(i)), headers=headers)
        if result.status_code != 200:
            log.critical("Error while accessing GHBD! Quitting!")
            exit(1)
        data = result.json()['data']
        for element in data:
            cat = element['category']['cat_title']
            catId = element['category']['cat_id']
            categoryDefinition = {
                'category' : cat,
                'id': catId
            }
            duplicateCategory = False
            for category in categories:
                if cat == category['category']:
                    duplicateCategory = True

            if duplicateCategory == False:
                categories.append(categoryDefinition)
            
            dorkDefinition = {}
            link = element['url_title']
            parsedLink = BeautifulSoup(link,"lxml")
            fullLink = ghdbBase+parsedLink.findAll('a')[0].attrs['href']
            dork = parsedLink.text
            fullDescriptionResponse = requests.get(fullLink, headers=headers)
            parsedResponse = BeautifulSoup(fullDescriptionResponse.content.decode('utf-8'),"lxml")
            description = parsedResponse.findAll('code')[0].text
            dorkDefinition['author'] = element['author']['name']
            dorkDefinition['dork'] = dork
            dorkDefinition['link'] = fullLink
            dorkDefinition['description'] = description
            dorkDefinition['category'] = {
                'title': cat,
                'id': catId
            }
            generalDorks.append(dorkDefinition)
        i += 120
        
    dorks['amount'] = numberOfDorks
    dorks['categories'] = categories
    dorks['dorks'] = generalDorks
    return dorks

try:   
    allDorks = scrapeGHDB()
    file = open('dorks.json', 'w')
    file.write(json.dumps(allDorks))
    file.close()
except:
    log.critical("Exception raised - Quitting")