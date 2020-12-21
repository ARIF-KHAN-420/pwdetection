from django.shortcuts import render
from .models import phishing_site_list
from .models import Legitimate_site_list
# Create your views here.

import pandas as pd

# importing required packages for feature extraction
from urllib.parse import urlparse,urlencode
from urllib.parse import urlsplit
import urllib
import urllib.request
from urllib.request import urlopen
from urllib.error import HTTPError
from urllib.error import URLError
import requests
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import tldextract
from tld import get_tld

# import model - Random Forest Classifier 
from sklearn.ensemble import RandomForestClassifier

# instantiate the model
forest = RandomForestClassifier(n_estimators=1000)


#                ==============  for 1st Model dataset import ==============

dataset = pd.read_csv('dataset/DatasetPhishing.csv')
data1 = dataset.drop(['Index'], axis = 1).copy()
data2 = data1.drop(['StatsReport'], axis = 1).copy()
data3 = data2.drop(['Favicon'], axis = 1).copy()
data4 = data3.drop(['AbnormalURL'], axis = 1).copy()
data5 = data4.drop(['UsingPopupWindow'], axis = 1).copy()
data6 = data5.drop(['PageRank'], axis = 1).copy()
data7 = data6.drop(['GoogleIndex'], axis = 1).copy()
data8 = data7.drop(['LinksInScriptTags'], axis = 1).copy()
data9 = data8.drop(['NonStdPort'], axis = 1).copy()
data10 = data9.drop(['RequestURL'], axis = 1).copy()
data11 = data10.drop(['ServerFormHandler'], axis = 1).copy()
data12 = data11.drop(['InfoEmail'], axis = 1).copy()
data = data12.sample(frac=1).reset_index(drop=True)

data.describe()

# Sepratating & assigning features and target columns to X & y

x = data.drop('class',axis=1)
y = data['class']

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(x, y, test_size = 0.01, random_state = 1)




#                        ================ for 2nd Model dataset import ==============

dataset2 = data12.drop(['AnchorURL'], axis = 1).copy()
dataset21 = dataset2.drop(['LinksPointingToPage'], axis = 1).copy()
dataset211 = dataset21.drop(['SubDomains'], axis = 1).copy()

dataset22 = dataset211.sample(frac=1).reset_index(drop=True)

# Sepratating & assigning features and target columns to X & y

X = dataset22.drop('class',axis=1)
Y = dataset22['class']
Xtrain, Xtest, Ytrain, Ytest = train_test_split(X, Y, test_size = 0.01, random_state = 2)


                                    #  Feature Extraction
                                    
# 1.  Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 2
    except:
        ip = 1
    return ip


# 2.  Finding the length of URL and categorizing (URL_Length)
def longURL(url):
    if len(url) < 54:
        length = 0
    elif len(url) < 76:
        length = 1
    else:
        length = 2            
    return length


#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                    r"tr\.im|link\.zip\.net"

# 3.  Checking for Shortening Services in URL (Tiny_URL)
def shortURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 2
    else:
        return 1

# 4. Checks the presence of @ in URL (Have_At)
def symbolAtTherat(url):
    if "@" in url:
        at = 1    
    else:
        at = 0    
    return at

# 5.Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0

# 6.  Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1            # phishing
    else:
        return 2            # legitimate

# 7. Checking for sub-domain in the Domain
def subdomain(urllink):

    def getDomain(*url):
        domain = urlparse(*url).netloc
        if re.match(r"^www.",domain):
            domain = domain.replace("www.","")
        return domain

    def find_subdomain(urlsearch):
        dotfound = 0
        subdom = (urlsearch.subdomain)
        if subdom == '':
            return 0
        else:
            for sentence in re.findall(r'[.]', subdom):
                if (sentence == '.'):
                    dotfound = dotfound + 1
            if (dotfound <= 1):
                return 0
            elif (dotfound == 2):
                return 1
            else:
                return 2
    d = getDomain(urllink)

    d2 = tldextract.extract(d)
    d3 = find_subdomain(d2)
    return d3

# 8. Existence of “HTTPS” (ssl certificate)

def https(url):
    b = 0
    try:
        requests.get(url) 
        b =1
    except:
        b=2
    return b

#9.  Domain Registrtation Lengtth 
def DomainRegistrationLength(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date,str):
        try:
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end/30) < 12):
            end = 2
        else:
            end = 1
    return end



# 10. Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpsDomainURL(url):
    try :
        domain = urlparse(url).netloc
        if 'https' in domain:
            return 2
        else:
            return 1
    except :
        return 2       
        
    


# 11. Anchor URL 
def anchortag(url):
    count = 0
    domainCounter = 0

    res = get_tld(url, as_object=True)
    dsd = res.domain

    html_page = urllib.request.urlopen(url)
    soup = BeautifulSoup(html_page, "html.parser")
    
    for link in soup.findAll('a'):
        count = count + 1
        for perLink in link:
            if perLink.find(dsd):
                domainCounter = domainCounter + 1
    if(count == 0):
        return 0
    else:
        newCount = count- domainCounter
        percentage = (newCount*100)/count

    def anchortagCount(count):
        if percentage <31:
            return 0
        elif (count <68):
            return 1
        else :
            return 2
    return anchortagCount(count)



# 12.Checks the number of forwardings (Web_Forwards)    
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 1:
            return 0
        elif len(response.history) <= 4:
            return 1
        else:
            return 2


# 13.Checks the effect of mouse over on status bar (Mouse_Over) (StatusBarCust)
def mouseOver(response): 
    if response == "" :
        return 2
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 2
        else:
            return 1


# 14.Checks the status of the right click attribute (Right_Click) 
def disableRightClick(response):
    if response == "":
        return 2
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 1
        else:
            return 2

# 15. IFrame Redirection (iFrame)
def iframeRedirection(response):
    if response == "":
        return 2
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 1
        else:
            return 2


# 16.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
        try:
            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        except:
            return 2
    if ((expiration_date is None) or (creation_date is None)):
        return 2
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 2
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain/30) < 12):
            age = 2
        else:
            age = 1
    return age

# 17.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        #Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 2
    if rank <100000:
        return 0
    else:
        return 1

# 19. Link Point To page 

def linkpointtopage(url):
    r = requests.get(url)

    soup = BeautifulSoup(r.text, "html.parser")
    
    count = 0

    for link in soup.find_all('a'):
        link.get('href')
        count += 1

    def linkToPage(count):
        if count == 0:

            return 2
        elif count < 2:
            return 1
        else:
            return 0
    return linkToPage(count)


                                # For 2nd Model Start 

def sceondModel(url):
     
    #Function to extract features
    def featureExtraction(url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        try:
            response = requests.get(url)
        except:
            response = ""
            
        features = []
        #features call
        features.append(havingIP(url))
        features.append(longURL(url))
        features.append(shortURL(url))
        features.append(symbolAtTherat(url))
        features.append(redirection(url))
        features.append(prefixSuffix(url))
        features.append(https(url))
        features.append(1 if dns == 1 else DomainRegistrationLength(domain_name))
        features.append(httpsDomainURL(url))
        features.append(forwarding(response))
        features.append(mouseOver(response))
        features.append(disableRightClick(response))
        features.append(iframeRedirection(response))
        features.append(1 if dns == 1 else domainAge(domain_name))
        
        features.append(dns)
        
        features.append(web_traffic(url))
        
        return features
    return featureExtraction(url)
                                        # End 2nd Model


                                    # For 1st Model Start

def firstModel(url):
    
    #Function to extract features
    def featureExtraction(url):
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
        try:
            response = requests.get(url)
        except:
            response = ""
            
        features = []
        #features call
        features.append(havingIP(url))
        features.append(longURL(url))
        features.append(shortURL(url))
        features.append(symbolAtTherat(url))
        features.append(redirection(url))
        features.append(prefixSuffix(url))
        features.append(subdomain(url))
        features.append(https(url))
        features.append(1 if dns == 1 else DomainRegistrationLength(domain_name))
        features.append(httpsDomainURL(url))
        features.append(anchortag(url))
        features.append(forwarding(response))
        features.append(mouseOver(response))
        features.append(disableRightClick(response))
        features.append(iframeRedirection(response))
        features.append(1 if dns == 1 else domainAge(domain_name))
        
        features.append(dns)
        
        features.append(web_traffic(url))
        features.append(linkpointtopage(url))
        
        return features
    return featureExtraction(url)
# End 1st model 

#Check URL have http or https
def is_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return 'https_or_http_not_found'


#Check url exist in the internet
def validurl(url):
    try:
        urllib.request.urlopen(url)
    except HTTPError as e:
        return ("HTTP_error")
    except URLError as e:
        return "Server_not_found"
    else:
        return True

# view.actionPhishingWD
def actionPhishingWD(request):
    if request.method == 'POST':
        data ={'c' : request.POST.get('url')}
        url2 = data['c']
        
        def remove(string):
                return string.replace(" ", "")
            
        url = remove(url2)
        
        def tldCheek(url):
            try:
                get_tld(url, as_object=True)
                return True
            except:
                return False
            
        if tldCheek(url) == False:
            data={'z' : 'please input a valid URL or Link','b' : url}
            
        else:
            def mainFunction(url):
                if (is_url(url) == True ):
                    if (validurl(url) == True):
                        result = firstModel(url)
                    else:
                        result = validurl(url)
                        return result
                else:
                    result = is_url(url)  
                    return result
                return result

            value = mainFunction(url)
            
            if (value == 'Server_not_found' or value == 'HTTP_error' or value == 'https_or_http_not_found'):
                forest.fit(Xtrain, Ytrain)
                answer = forest.predict([sceondModel(url)])
                
            else:
                forest.fit(X_train, y_train)
                answer = forest.predict([value])
            
            if (answer == 0):
                if Legitimate_site_list.objects.filter(link = url).exists():
                    data['link'] = 'link_exists' 
                else:
                    link_save = Legitimate_site_list(link = url)
                    link_save.save()
                data = {'a':'Legitimate Website', 'b' : url}
            else:
                if phishing_site_list.objects.filter(link = url).exists():
                    data['link'] = 'link_exists' 
                else:
                    link_save = phishing_site_list(link = url)
                    link_save.save()
                data = {'a':'Phishing Website', 'b' : url}
    else:
        data = {'d' : 'No Request Found'}
    return render(request,'index.html',data)