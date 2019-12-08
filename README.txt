
Digilyzer: Open-source alternatief voor de DigiD app
====================================================

Digilyzer is een open-source alternatief voor de DigiD app.
Digilyzer werkt op Windows en Linux PCs, dus niet als mobiele app.

Op dit moment is Digilyzer experimentele software en ongeschikt voor
serieus gebruik. Maar mogelijk is het een eerste stap op weg naar
betrouwbare, free open-source DigiD software.


WAARSCHUWING:

 * Ondeskundig gebruik van Digilyzer kan de beveiliging van uw DigiD
   in gevaar brengen. Momenteel is Digilyzer alleen geschikt voor
   computerprogrammeurs, niet voor eindgebruikers.

 * Digilyzer is onofficiele, experimentele software. Het is niet gemaakt
   of getest door de overheid. Digilyzer kan plotseling stoppen met
   werken na updates van het officiele DigiD systeem.

 * Geef nooit uw DigiD gegevens aan onbekende software, apps of websites.
   Gebruik alleen de officiele DigiD website en de officiele DigiD app
   van de rijksoverheid.



Voordelen van Digilyzer
-----------------------

De source code van Digilyzer is openbaar. Hierdoor kan iedereen
controleren hoe Digilyzer werkt. Bovendien kan het programma worden
aangepast om te werken op alle soorten computers en telefoons.

Daarentegen is de officiele DigiD app alleen beschikbaar via de app
stores van Google en Apple. De werking van de DigiD app is bovendien
geheim, waardoor niemand kan controleren welke gegevens de app doorgeeft
aan de overheid.

Digilyzer werkt op Windows en Linux PCs, in tegenstelling tot de
officiele DigiD app die alleen werkt op mobiele apparaten. Apparaten die
je overal mee naartoe neemt terwijl de DigiD app beveiligd is met een
pincode van slechts 5 cijfers.



Veiligheidsrisicos van Digilyzer
--------------------------------

Digilyzer heeft momenteel zoveel nadelen dat het gebruik ervan is
af te raden. Het is veiliger om alleen de officiele DigiD website en
de officiele DigiD app van de rijksoverheid te gebruiken.

Omdat Digilyzer onofficiele software is, kun je er als gebruiker niet
op vertrouwen dat het doet wat het belooft. Het is zeer riskant om je
DigiD gegevens in te voeren in onbekende software zoals Digilyzer.
Wie toch Digilyzer wil gebruiken, moet eerst de Python code zorgvuldig
bestuderen en begrijpen. Pas daarna kun je erop vertrouwen dat Digilyzer
geen misbruik maakt van je gegevens.

Digilyzer bewaart inloggegegens in een bestand op de computer.
(De officiele DigiD app bewaart deze gegevens op de mobiele telefoon.)
Als dit bestand in verkeerde handen valt, kunnen onbevoegden inloggen op
je DigiD account. In het algemeen zijn PCs en laptops slechter beveiligd
dan telefoons en tablets. Op PCs zijn applicaties niet goed van elkaar
gescheiden. Een onbetrouwbaar programma of website kan daardoor de hele
PC overnemen.

De source code van Digilyzer is niet gecontroleerd door experts.
Er kunnen dus fouten in Digilyzer zitten die de beveiliging van je DigiD
in gevaar brengen.



Werking van Digilyzer
---------------------

Digilyzer maakt verbinding met de DigiD server van de overheid op
dezelfde manier als de officiele DigiD app dat doet. De DigiD server
ziet geen verschil tussen Digilyzer en de echte DigiD app.

Digilyzer is gebaseerd op versie 5.13.2 van de DigiD app. Als nieuwere
versies van de app op een andere manier met de server communiceren, zal
Digilyzer waarschijnlijk niet meer werken.

Digilyzer is gemaakt in Python en gebruikt de volgende libraries:
 * Python 3.7.3
 * numpy 1.16.2
 * urllib3 1.24.1
 * cryptography 2.6.1
 * Pillow 5.4.1
 * PyGObject 3.30.4 (alleen voor Linux)

Gebruik Digilyzer alleen op een goed beveiligde computer.
Digilyzer bewaart gegevens in een bestand "digilyzer.settings" in de
home directory. In combinatie met je pincode, geeft dit bestand toegang
tot je DigiD account. Als dit bestand in verkeerde handen valt, kunnen
onbevoegden inloggen op je DigiD account. Als dit bestand kwijtraakt,
kun je niet meer inloggen met Digilyzer. Het bestand is vergelijkbaar
met de gegevens die de officiele DigiD app op je smartphone bewaart.

Net als de officiele app, moet Digilyzer eerst geactiveerd worden
voordat je ermee kunt inloggen. Activeren gaat als volgt:

 1. Geef het commando "python3 digilyzer.py activate".

 2. Kies eventueel een wachtwoord om Digilyzer gegevens te beveiligen.

 3. Vul je gebruikersnaam en wachtwoord in (dezelfde als op de DigiD
    website). Deze gegevens worden naar de DigiD server gestuurd om
    activatie mogelijk te maken. De officiele DigiD app doet dat
    namelijk ook.

 4. Kies een eigen pincode van 5 cijfers.

 5. Er wordt een activatiecode gestuurd via SMS of via een brief.

 6a. Indien SMS: Voer de activatiecode in via Digilyzer.

 6b. Indien brief: Wacht op de brief met de activatiecode.
     Geef dan het commando "python3 digilyzer.py complete".
     Voer de activatiecode in via Digilyzer.
     Voer je pincode in om activatie te bevestigen.

Eenmaal geactiveerd, kun je Digilyzer gebruiken om in te loggen op
websites zoals digid.nl, de belastingdienst of zorgverzekeraars.
Inloggen (authenticatie) gaat als volgt:

 1. Geef het commando "python3 digilyzer.py authenticate".

 2. Digilyzer toont een "koppelcode".
    Vul deze koppelcode in op de website waar je wil inloggen.

 3. De website laat een QR code zien.
    Maak een screenshot van de QR code en geef deze aan Digilyzer.

 4. Digilyzer toont een authenticatieverzoek.
    Controleer of dat klopt met de website waar je wil inloggen.
    Voer je pincode in om activatie te bevestigen.

Sommige functies van de officiele DigiD app, ontbreken in Digilyzer.
Voorbeelden van ontbrekende functies zijn: pincode veranderen,
paspoort controle via NFC, inloggen op mobiele apps.



Geen ondersteuning
------------------

Digilyzer is onofficiele, experimentele software. Het is niet gemaakt
of getest door de overheid. Er is geen enkele garantie dat deze software
correct werkt. Bovendien kan Digilyzer plotseling stoppen met werken na
updates van het officiele DigiD systeem.

Er is niemand beschikbaar die vragen over het gebruik van Digilyzer
kan beantwoorden.

De DigiD helpdesk weet niets over Digilyzer en kan geen ondersteuning
bieden bij het gebruik ervan.

--
