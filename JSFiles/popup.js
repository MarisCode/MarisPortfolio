function openPopup(x) {

    /* Start and end tags that are same for all the popup windows */
    var start = '<section class="popup_box column">' +
                    '<div class="close_popup_bar">' +
                        '<button class="close_popup" onclick="closePopup()">X</button>' +
                    '</div>' +
                    '<section class="popup_content column">';
    var end = '</section></section>'

    /* Popup content for Fribago */
    if (x === 'fribago') {

        var header =    '<figure class="project_img">' +
                            '<a href="https://www.fribago.com" target="_blank">' +
                                '<img class="project_logo" src="images/fribago_logo.png" alt="FribaGo-logo">' +
                            '</a>' +
                        '</figure>';

        var summary =   '<blockquote class="popup_quote" cite="https://www.fribago.com">' +
                            '<section class="column quote_wrap">' +
                                '<p class="quote_p">' +
                                    'FribaGo.com on frisbeegolfarin sivusto, jonka tarkoituksena on tarjota uusi vaihtoehto frisbeegolf kierrosten tulosten kirjaamiseen ja tilastointiin.' +
                                '</p>' +
                                '<p class="quote_p">' +
                                    'FribaGon päätavoitteena on tulosten kirjaamisen helppous ja pelaajan kehityksen seuranta erilaisia tilastoja tarjoamalla. Toinen tärkeä tavoite on kerätä radoista tietoa helpottamaan pelaamista käyttäjälle uusilla radoilla.' +
                                '</p>' +
                            '</section>' +
                            '<p class="source_p">' +
                                '<span class="accent">fribago.com</span>' +
                            '</p>' +
                        '</blockquote>' +
                        '<section class="column">' +
                            '<h2>FribaGo</h2>' +
                            '<p class="info_p">' +
                                'FribaGo-projekti alkoi keväällä 2023, kun opiskelukaverini kyseli halukkaita frisbeegolf-sovelluksen kehittämiseen. Tarkoituksena oli saada kesälle koodailtavaa tuntuman ylläpitämiseksi. Alkutunnustelujen jälkeen FribaGoa jäi työstämään neljä opiskelijaa, ja työ jatkuu saman tiimin voimin edelleen. Tällä hetkellä FribaGo on testausvaiheessa muutaman kymmenen lajin harrastajan avustuksella. FribaGo-työryhmä on tiiviisti yhteydessä testiryhmään, ja sovellusta pyritään parantamaan toiveiden mukaan.' +
                            '</p>';
        
        var part1 =         '<h2>Päävastuualueeni</h2>' +
                            '<p class="info_p">' +
                                'Päävastuualueinani ovat olleet FribaGon <span class="accent">sivuston väritys ja ulkoasu</span> sekä <span class="accent">Hae rata -hakukoneen toteutus</span>. Lisäksi olen osallistunut aktiivisesti eri toimintojen suunnitteluun.' +
                            '</p>';
        
        var part2 =         '<h3>Ulkoasu</h3>' +
                            '<p class="info_p">' +
                                'Suunnittelin FribaGon ulkoasun <span class="accent">Figmalla</span>. Väreiksi valikoituivat musta, valkoinen, harmaan eri sävyt sekä minttu. Loppuvuodesta 2023 julkaistiin myös testiryhmässä toivottu <span class="accent">vaalea teema</span>, jonka suunnittelu ja toteutus on pääosin minun käsialaani. Tällä hetkellä vaalea teema on tiukasta aikataulusta johtuen toteutettu vain muuttamalla tumman teeman värejä. Tavoitteenani on kehittää teemoja omiin suuntiinsa mahdollisimman selkeiksi ja silmää miellyttäviksi kokonaisuuksiksi.</p>';
        
        var part3 =         '<h3>Hakukone</h3>' +
                            '<p class="info_p">' +
                                'Olen toteuttanut FribaGoon <span class="accent">Hae rata</span> -hakukoneen. Se hakee ratoja tietokannasta, jonne sovellukseen syötetyt frisbeegolfradat tallennetaan. Hakukone on toteutettu <span class="accent">jQueryn</span> ja <span class="accent">Ajaxin</span> avulla, jolloin erillistä hakunappia ei tarvita. Hakutulokset päivittyvät, kun jokin hakukriteeri muuttuu.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Hakukriteereitä ovat radan nimi, paikkakunta, väylien lukumäärä, väylien kokonaispituus metreinä, vaativuustaso sekä vapaa haku, joka hakee ratoja radan nimen, paikkakunnan sekä radalle annetun kuvaustekstin perusteella. Nämä kaikki on yhdistetty <span class="accent">yhdessä SQL-lauseessa</span>, jolloin jokainen kenttä ja nappi vaikuttaa lopulliseen hakutulokseen.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Hakutulokset tulevat näkyviin linkkeinä, jotka johtavat radan sivulle. Sitä kautta pääsee aloittamaan kierroksen kyseisellä radalla. Hakukonetta pääsee käyttämään kirjautumatta, mutta pelaamiseen vaaditaan rekisteröityminen.' +
                            '</p>';

        var content = start + header + summary + part1 + part2 + part3 + end;
    }

    /* Popup content for Kirjanpitäjä */
    else if (x === 'kirjanpitaja') {

        header =        '<figure class="project_img">' +
                            '<img class="project_logo" src="images/kirjanpitaja_logo.png" alt="Kirjanpitäjä-logo">' +
                        '</figure>';

        summary =       '<section class="column">' +
                            '<h2>Yleistä Design Factory Projectista</h2>' +
                            '<p class="info_p">' +
                                'Design Factory Project -kurssi oli kokonaisvaltainen harjoitus <span class="accent">tiimityöskentelystä asiakasprojektissa</span>. Tarkoitus oli rakentaa pienyrittäjille tarkoitettu jotain kirjanpidon osa-aluetta hoitava kevytsovellus tai sen käyttöliittymäsuunnitelma. Sovelluksen tuli olla mahdollisimman selkeä, helppokäyttöinen ja käyttäjää ohjaava. Toimeksiantaja oli Taloushallinnon Ratkaisutoimisto Oikia. Projektin kesto oli kahdeksan viikkoa.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Seitsemänhenkisen tiimini osa-alue oli <span class="accent">tositteet ja niiden hallinta</span>. Päätimme toteuttaa toimivan web-pohjaisen sovelluksen tositteiden tallentamiseen ja käsittelyyn käyttämällä <span class="accent">HTML:ää, CSS:ää, JavaScriptiä, PHP:tä sekä MySQL:ää</span>. Toteutimme projektin koulun tarjoamalla palvelimella.' +
                            '</p>';

        part1 =             '<h2>Päävastuualueeni</h2>' +
                            '<p class="info_p">' +
                                'Vastuualueenani oli toteuttaa <span class="accent">organisaation hallinta -sivu</span> toiminnallisuuksineen. Sivun kautta voi lisätä sovellukseen organisaatioita, muokata niiden tietoja ja valita organisaation, jonka tositteita käsitellään.' +
                            '</p>';

        part2 =             '<h3>Organisaation lisääminen</h3>' +
                                '<p class="info_p">' +
                                    'Uuden organisaation lisääminen tapahtuu lomakkeen kautta. Lomake ohjaa käyttäjää esimerkiksi Y-tunnuksen ja tilinumeron oikean muodon osalta, eikä tietoja voi tallentaa virheellisessä muodossa. Yrityksen tiedot tallentuvat tietokantaan, ja niihin pääsee käsiksi vain käyttäjä, joka tiedot on syöttänyt.' +
                                '</p>';

        part3 =             '<h3>Organisaation tietojen muokkaus</h3>' +
                            '<p class="info_p">' +
                                'Muokkaa organisaatiota -välilehdellä on alasvetovalikko, johon haetaan tietokannasta kaikkien kirjautuneen käyttäjän hallitsemien organisaatioiden nimet. Valikosta valitun organisaation tietokantaan tallennetut tiedot haetaan Lisää organisaatio -lomaketta vastaavalle lomakkeelle. Tietoja voi muokata, ja muokatut tiedot tallentuvat tietokantaan ylikirjoittaen vanhat tiedot.' +
                            '</p>';

        var part4 =         '<h3>Organisaation valinta</h3>' +
                            '<p class="info_p">' +
                                'Valitse organisaatio -välilehdeltä pääsee valitsemaan organisaation, jonka tositteita haluaa käsitellä. Alasvetovalikkoon haetaan tietokannasta kaikkien käyttäjän hallitsemien organisaatioiden nimet. Valitun organisaation tiedot aukeavat valikon alle, jotta voidaan varmistua, että ollaan valitsemassa oikeaa organisaatiota. Halutun organisaation valinta vahvistetaan painikkeesta, ja valitun organisaation nimi tulee näkyviin yläpalkkiin. Tästä eteenpäin kaikki syötetyt/muokatut/poistetut tositteet kirjataan tämän organisaation kirjanpitoon. Jos käyttäjällä on vain yksi organisaatio, se on automaattisesti valittuna käyttäjän sisäänkirjautumisesta lähtien.' +
                            '</p>';

        var more =         '<h2>Lisää projektista</h2>' +
                            '<p class="info_p">' +
                                'Projekti oli haastava koitos, sillä koulutuksen puolesta meillä ei ollut valmiuksia toteuttaa sovellusta tässä mittakaavassa. Tiimin jäsenillä oli harrastuneisuutta ja opiskelimme uutta itsenäisesti projektin edetessä. Sovimme tiimin kanssa jo alkuvaiheessa, että asetamme tavoitteen korkealle ja pyrimme toetuttamaan mahdollisimman käyttövalmiin sovelluksen.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Ensimmäiseksi perehdyimme pienyritysten kirjanpidon lakeihin, säädöksiin ja tositteisiin. Lisäksi selvitetimme asiakkaalta, mitkä ominaisuudet koettiin tärkeimmiksi. Tiukan aikataulun vuoksi oli priorisoitava toteutettavia toimintoja ja ominaisuuksia.' +
                            '</p>' +
                            '<h3>Responsiivisuus</h3>' +
                            '<p class="info_p">' +
                                'Halusimme toteuttaa sovelluksen näkymän niin, että näyttöä ei tarvitse missään vaiheessa scrollata. Otimme huomioon näyttökoot tabletista suuriin näyttöihin. Teimme CSS:ään Media Queryja, joissa huomioimme eri näyttökokoja ja näytön tai selaimen skaalauksen 125 %:iin asti. Huolehdin, että Organisaation hallinta -sivu toimii moitteetta näillä kriteereillä.' +
                            '</p>' +
                            '<h3>Scrum</h3>' +
                            '<p class="info_p">' +
                                'Projekti toteutettiin Scrumia käyttäen. Suunnittelimme sprintit (3 kpl) ja pidimme kirjaa projektin vaiheista Jirassa. Suunnittelupalaverit, dailyt, reviewit ja retrospektiivit kirjasimme Confluenceen. Toimin Scrum masterina yhden sprintin ajan. Harjoituksen vuoksi vaihdoimme Scrum masterin jokaiseen sprinttiin.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Asiakkaan edustaja oli paikalla review-tilaisuuksissa. Nämä tapaamiset olivat kullan arvoisia, sillä niissä saimme tarkennuksia ja palautetta, joiden perusteella pystyimme kehittämään sovellusta asiakkaan toivomaan suuntaan. Palaute oli alusta asti rakentavaa ja sen avulla pystyimme toteuttamaan tositteiden käsittelyyn sovelluksen, johon asiakas oli tyytyväinen.' +
                            '</p>' +
                        '</section>';

        var content = start + header + summary + part1 + part2 + part3 + part4 + more + end;
    }

    /* Popup content for Ravintola Line */
    else if (x === 'line') {

        header =        '<figure class="project_img">' +
                            '<img class="project_logo" src="images/line_logo.png" alt="Ravintola Line -logo">' +
                        '</figure>';

        summary =       '<section class="column">' +
                            '<h2>Yleistä projektista</h2>' +
                            '<p class="info_p">' +
                                'Ravintola Line on kuvitteellisen ravintolan web-sivu, joka suunniteltiin ja toteutettiin yhden moduulin (sis. kolme kurssia) aikana kolmen opiskelijan ryhmässä. Ensimmäisessä vaiheessa teimme ulkoasusuunnitelman, jonka pohjalta toteutimme sivuston HTML- ja CSS-puolen. Seuraavassa vaiheessa toteutimme sivustolle Admin-osion, jonka kautta voi hallita tietokantaan tallennettuja ruokalajeja. Kolmannessa vaiheessa toteutimme vastaavan sivuston WordPressin avulla. Toteutimme projektin koulun tarjoamalla palvelimella. Listaan alle kurssit, ja mitä niiden myötä tehtiin.' +
                            '</p>';

        part1 =             '<h2>Staattisen verkkosivun rakentaminen</h2>' +
                            '<p class="info_p">' +
                                'Suunnittelimme yhdessä sivuston ulkoasun pääpiirteittäin. Toteutin lopullisen etusivun ulkoasusuunnitelman Figmalla. Yksi tiimiläisistä laati HTML-rungon etusivulle Bootstrapia hyödyntäen, ja samaa runkoa käytimme muiden sivujen rakentamisessa. Jokainen tiimiläinen teki sivustolle yhden sivun, ja minun sivuni oli Pöytävaraus-sivu.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Kiinnitimme erityistä huomiota kurssin aiheina olleisiin saavutettavuuteen, responsiivisuuteen, semanttiseen koodiin sekä koodin selkeyteen ja kommentointiin. Kommentoinnin tärkeys korostui projektissa, jossa useampi henkilö käsitteli samoja koodeja.' +
                            '</p>';

        part2 =             '<h3>Päävastuualueeni: Pöytävaraus-sivu</h3>' +
                            '<p class="info_p">' +
                                'Toteutin pöytävaraussivulle lomakkeen, jonka kautta voi varata pöydän haluamanaan ajankohtana valitsemalleen henkilömäärälle. Toiminnallisuuksia ei toteutettu.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Tutustuin kurssilla Figmaan, joka on näppärä työkalu ulkoasusuunnitelmien laatimiseen. Uutena asiana tuli myös semanttinen koodi. Se on olennainen osa saavutettavuutta, johon perehdyimme myös kurssilla. Sivuston saavutettavuus on tarkistettu Wave-työkalulla.' +
                            '</p>';

        part3 =             '<h2>Web-ohjelmointi</h2>' +
                            '<p class="info_p">' +
                                'Web-ohjelmointi-kurssilla toteutimme ravintolan kotisivulle ylläpitosivut. Ylläpitosivujen kautta voidaan lisätä, muokata ja poistaa tuotetietoja tietokannasta sekä hallita ruokalajien kuvia palvelimella. Ylläpitosivut ovat yhteydessä ravintolan kotisivujen Menu-sivuun, jossa ruokalajit näkyvät kategorioittain. Lisäksi Menu-sivulle on toteutettu kuvagalleria JavaScriptin avulla.' +
                            '</p>';

        part4 =             '<h3>Päävastuualueeni: Ruokalajien lisäys tietokantaan</h3>' +
                            '<p class="info_p">' +
                                'Ruokalajien lisääminen tapahtuu Admin-osiossa lomakkeen kautta. Samalla lomakkeella liitetään myös ruokalajin kuva. Kaikki tiedot ovat pakollisia, sillä ne tulevat näkyviin Menun-sivun ruokalistaan. Lisäksi on rajoituksia kuvan koolle ja tiedostotyypille. Kuvat tallennetaan palvelimelle, ja tietokantaan tallennetaan viittaus kuvan nimeen.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Lomake on toteutettu HTML:llä, toiminnallisuudet JavaScriptillä ja tietokannan hallinta PHP:lla. Lisäksi tein muutamia pieniä, mutta käteviä JavaScript-koodeja: mm. lomakkeille syötettyjen pilkkujen muuttaminen pisteiksi tietokantaa varten ja toisinpäin Menu-sivun ruokalistaan sekä määrittely, mihin kenttään kursori sijoittuu sivun latauduttua.' +
                            '</p>';

        var part5 =         '<h3>Päävastuualueeni: Menu-sivun hallinta</h3>' +
                            '<p class="info_p">' +
                                'Ruokalajien tiedot haetaan tietokannasta Menu-sivun ruokalistaan, omien kategorioidensa alle. Kaikki tietokannassa olevat ruokalajit tulevat näkyviin ruokalistalle. Optimaalinen tilanne olisi, jos ruokalistalla näkyvät ruokalajit voisi valita suuremmasta datamäärästä, mutta aika loppui kesken tämän toiminnon osalta.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Menu-sivu on .php-tiedosto. Ruokalajit tietoineen haetaan tietokannasta kategorian mukaan (alkuruoka, pääruoka, jälkiruoka) ja esitetään Menu-sivulla omissa osioissaan.' +
                            '</p>';

        var part6 =         '<h3>Päävastuualueeni: Menu-sivun kuvagalleria</h3>' +
                            '<p class="info_p">' +
                                'Jokaisen ruokalajikategorian vieressä on yhden kuvan kuvapaikka. Kunkin ruokalajin kohdalla on pieni kuvake, jota klikkaamalla ruokalajin kuva avautuu oman kategoriansa kuvapaikkaan. Kuvagalleria on toteutettu JavaScriptillä.' +
                            '</p>' +
                            '<p class="info_p">' +
                                'Menu-sivulla on käytetty kuvapalveluista löytyneitä ilmaisia kuvia. Olen rajannut ja käsitellyt kuvat sopiviksi Photopea-ohjelmalla.' +
                            '</p>';

        var part7 =         '<h2>Sisällönhallintajärjestelmät</h2>' +
                            '<p class="info_p">' +
                                'Tällä kurssilla tutustuimme WordPressiin. Tavoitteena oli laatia mahdollisimman saman näköinen sivusto kuin aiemmissa vaiheissa tehty luomalla valmiista teemasta lapsiteema ja käyttää plugineja toiminnallisuuksien toteutukseen.' +
                            '</p>';

        var part8 =         '<h3>Päävastuualueeni: Etusivu, Pöytävaraukset ja Yhteystiedot</h3>' +
                            '<p class="info_p">' +
                                'Valitsemastamme teemasta luotiin lapsiteema, johon rakensin etusivun, pöytävaraussivun sekä yhteystietosivun.' +
                            '</p>'

        var part9 =         '<h3>Päävastuualueeni: Pöytävaraussivun toiminnallisuudet ja responsiivisuus</h3>' +
                            '<p class="info_p">' +
                                'Toteutin Pöytävaraussivun lomakkeen Forminator-pluginilla. Varausten käsittelyä varten asennettiin wpDataTables-plugin ja siihen lisäosana wpDataTables integration for Forminator Forms -plugin. Varauksen lähettämisen jälkeen asiakas saa sähköpostiinsa tervetulotoivotuksen ja varauksen tiedot. Varausten tiedot listautuvat myös taulukkoon WordPressin Dashboardiin. Taulukosta näkee kaikki varaukset tietoineen.</p><p class="info_p">Kuten aikaisemmassakin vaiheessa, kiinnitimme huomiota responsiivisuuteen. Huolehdin pöytävaraussivun responsiivisuuden toimivaksi.' +
                            '</p>'

        var part10 =        '<h3>Päävastuualueeni: Yhteystiedot-sivun kartta</h3>' +
                            '<p class="info_p">' +
                                'Yhteystiedot-sivulla oleva kartta on toteutettu WP Map Block -pluginilla.' +
                            '</p>' +
                        '</section>';
        
        content = start + header + summary + part1 + part2 + part3 + part4 + part5 + part6 + part7 + part8 + part9 + part10 + end;
    }

    else content = "<h1>Jokin meni pieleen.</h1>";


    document.querySelector('#popup').innerHTML = content;
    document.querySelector('#popup').style.display = "block";

}

function closePopup() {
    document.querySelector('#popup').style.display = "none";
}
