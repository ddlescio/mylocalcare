"""Traduzioni dell'interfaccia MyLocalCare, senza contenuti scritti dagli utenti."""

import base64
import html
import json
import re
from pathlib import Path

from i18n_catalog import PATTERN_ROWS, PHRASE_ROWS

SUPPORTED_LANGUAGES = {
    "it": {"label": "Italiano", "flag": "🇮🇹", "short": "IT"},
    "en": {"label": "English", "flag": "🇬🇧", "short": "EN"},
    "fr": {"label": "Français", "flag": "🇫🇷", "short": "FR"},
    "es": {"label": "Español", "flag": "🇪🇸", "short": "ES"},
    "de": {"label": "Deutsch", "flag": "🇩🇪", "short": "DE"},
    "ro": {"label": "Română", "flag": "🇷🇴", "short": "RO"},
    "uk": {"label": "Українська", "flag": "🇺🇦", "short": "UA"},
    "fil": {"label": "Filipino", "flag": "🇵🇭", "short": "FIL"},
}

LEGAL_DOCUMENT_VERSION = "mylocalcare_privacy_termini_2026_v2"


TRANSLATIONS = {
    "legal.official_language_notice": {
        "it": "Il testo legale ufficiale è quello in italiano.",
        "en": "Courtesy translation. In case of discrepancies, the official Italian text prevails.",
        "fr": "Traduction de courtoisie. En cas de divergence, le texte officiel italien prévaut.",
        "es": "Traducción de cortesía. En caso de discrepancia, prevalece el texto oficial en italiano.",
        "de": "Unverbindliche Übersetzung. Bei Abweichungen ist der offizielle italienische Text maßgeblich.",
    },
    "legal.version_label": {
        "it": "Versione", "en": "Version", "fr": "Version", "es": "Versión",
        "de": "Version", "ro": "Versiune", "uk": "Версія", "fil": "Bersyon",
    },
    "legal.profile_cards_privacy_title": {
        "it": "3-bis. Schede strutturate e controlli facoltativi",
        "en": "3-bis. Structured cards and optional checks",
        "fr": "3-bis. Fiches structurées et contrôles facultatifs",
        "es": "3-bis. Fichas estructuradas y comprobaciones opcionales",
        "de": "3-bis. Strukturierte Profilkarten und freiwillige Prüfungen",
        "ro": "3-bis. Fișe structurate și verificări opționale",
        "uk": "3-bis. Структуровані картки та добровільні перевірки",
        "fil": "3-bis. Structured cards at opsyonal na pagsusuri",
    },
    "legal.profile_cards_privacy_body": {
        "it": "L’utente può creare schede strutturate relative a esperienze, formazione e certificazioni. Se il profilo è pubblico, i dati della scheda sono visibili ai visitatori, escluso il codice della qualifica. La richiesta e l’esito del controllo, il metodo utilizzato, le note interne strettamente necessarie e una copia testuale dei dati controllati sono trattati per erogare la funzione, prevenire abusi e documentare il controllo svolto.",
        "en": "Users may create structured cards about experience, education and certifications. If the profile is public, the card details are visible to visitors, except for the qualification code. The check request and outcome, method used, strictly necessary internal notes and a text snapshot of the checked details are processed to provide the feature, prevent abuse and document the check performed.",
        "fr": "L’utilisateur peut créer des fiches structurées concernant ses expériences, sa formation et ses certifications. Si le profil est public, les données de la fiche sont visibles par les visiteurs, à l’exception du code de qualification. La demande et le résultat du contrôle, la méthode utilisée, les notes internes strictement nécessaires et une copie textuelle des données contrôlées sont traités afin de fournir la fonctionnalité, prévenir les abus et documenter le contrôle effectué.",
        "es": "El usuario puede crear fichas estructuradas sobre experiencia, formación y certificaciones. Si el perfil es público, los datos de la ficha son visibles para los visitantes, excepto el código de la cualificación. La solicitud y el resultado de la comprobación, el método utilizado, las notas internas estrictamente necesarias y una copia textual de los datos comprobados se tratan para prestar la función, prevenir abusos y documentar la comprobación realizada.",
        "de": "Nutzer können strukturierte Profilkarten zu Erfahrung, Ausbildung und Zertifizierungen erstellen. Ist das Profil öffentlich, sind die Angaben für Besucher sichtbar; ausgenommen ist der Qualifikationscode. Prüfanfrage und -ergebnis, verwendete Methode, unbedingt erforderliche interne Notizen und eine Textkopie der geprüften Angaben werden verarbeitet, um die Funktion bereitzustellen, Missbrauch zu verhindern und die Prüfung zu dokumentieren.",
        "ro": "Utilizatorul poate crea fișe structurate despre experiență, educație și certificări. Dacă profilul este public, datele fișei sunt vizibile vizitatorilor, cu excepția codului calificării. Solicitarea și rezultatul verificării, metoda folosită, notele interne strict necesare și o copie textuală a datelor verificate sunt prelucrate pentru furnizarea funcției, prevenirea abuzurilor și documentarea verificării.",
        "uk": "Користувач може створювати структуровані картки про досвід, освіту та сертифікації. Якщо профіль відкритий, дані картки видимі відвідувачам, крім коду кваліфікації. Запит і результат перевірки, використаний метод, лише необхідні внутрішні примітки та текстова копія перевірених даних обробляються для надання функції, запобігання зловживанням і документування перевірки.",
        "fil": "Maaaring gumawa ang user ng structured cards tungkol sa karanasan, edukasyon, at certifications. Kung public ang profile, makikita ng mga bisita ang detalye ng card maliban sa qualification code. Pinoproseso ang request at resulta ng pagsusuri, paraang ginamit, mahigpit na kinakailangang internal notes, at text snapshot ng sinuring detalye upang maibigay ang feature, maiwasan ang abuso, at maidokumento ang ginawang pagsusuri.",
    },
    "legal.profile_cards_privacy_retention": {
        "it": "Su richiesta dell’utente, MyLocalCare può visionare un documento senza conservarne copia, consultare una fonte pubblica o contattare l’ente indicato. La scheda resta conservata finché l’utente la mantiene; la sua eliminazione o l’eliminazione dell’account rimuove anche lo storico collegato. Il minimo storico amministrativo è conservato solo per il tempo necessario a gestire controlli, sicurezza e contestazioni, salvo ulteriori obblighi di legge.",
        "en": "At the user’s request, MyLocalCare may view a document without keeping a copy, consult a public source or contact the named organisation. The card is kept while the user maintains it; deleting the card or account also removes the related history. The minimum administrative record is kept only as long as needed to manage checks, security and disputes, unless the law requires longer retention.",
        "fr": "À la demande de l’utilisateur, MyLocalCare peut consulter un document sans en conserver de copie, vérifier une source publique ou contacter l’organisme indiqué. La fiche est conservée tant que l’utilisateur la maintient ; la suppression de la fiche ou du compte supprime également l’historique associé. Le minimum d’historique administratif n’est conservé que le temps nécessaire à la gestion des contrôles, de la sécurité et des contestations, sauf obligation légale contraire.",
        "es": "A petición del usuario, MyLocalCare puede revisar un documento sin conservar una copia, consultar una fuente pública o contactar con la entidad indicada. La ficha se conserva mientras el usuario la mantenga; al eliminar la ficha o la cuenta también se elimina el historial relacionado. El mínimo historial administrativo se conserva solo durante el tiempo necesario para gestionar comprobaciones, seguridad y reclamaciones, salvo obligaciones legales adicionales.",
        "de": "Auf Wunsch des Nutzers kann MyLocalCare ein Dokument einsehen, ohne eine Kopie aufzubewahren, eine öffentliche Quelle prüfen oder die angegebene Stelle kontaktieren. Die Profilkarte wird gespeichert, solange der Nutzer sie behält; beim Löschen der Karte oder des Kontos wird auch der zugehörige Verlauf entfernt. Der erforderliche administrative Mindestnachweis wird nur so lange gespeichert, wie dies für Prüfungen, Sicherheit und Streitfälle nötig ist, sofern keine gesetzlichen Pflichten entgegenstehen.",
        "ro": "La cererea utilizatorului, MyLocalCare poate consulta un document fără a păstra o copie, poate verifica o sursă publică sau poate contacta instituția indicată. Fișa este păstrată cât timp utilizatorul o menține; ștergerea fișei sau a contului elimină și istoricul aferent. Istoricul administrativ minim este păstrat doar cât este necesar pentru verificări, securitate și contestații, cu excepția obligațiilor legale suplimentare.",
        "uk": "На запит користувача MyLocalCare може переглянути документ без збереження копії, перевірити відкрите джерело або зв’язатися із зазначеною установою. Картка зберігається, доки користувач її підтримує; видалення картки або облікового запису також видаляє пов’язану історію. Мінімальний адміністративний запис зберігається лише стільки, скільки потрібно для перевірок, безпеки та спорів, якщо закон не вимагає іншого.",
        "fil": "Kapag hiniling ng user, maaaring tingnan ng MyLocalCare ang isang dokumento nang hindi nagtatago ng kopya, kumonsulta sa pampublikong source, o kontakin ang nakasaad na institusyon. Itinatago ang card habang pinananatili ito ng user; kapag dinelete ang card o account, mabubura rin ang kaugnay na history. Ang minimum na administrative record ay itinatago lamang hangga’t kailangan para sa pagsusuri, seguridad, at dispute, maliban kung may ibang legal na obligasyon.",
    },
    "legal.profile_cards_terms_title": {
        "it": "5-bis. Schede dichiarate e controlli MyLocalCare",
        "en": "5-bis. User-declared cards and MyLocalCare checks",
        "fr": "5-bis. Fiches déclarées et contrôles MyLocalCare",
        "es": "5-bis. Fichas declaradas y comprobaciones de MyLocalCare",
        "de": "5-bis. Nutzerauskünfte und MyLocalCare-Prüfungen",
        "ro": "5-bis. Fișe declarate și verificări MyLocalCare",
        "uk": "5-bis. Заявлені дані та перевірки MyLocalCare",
        "fil": "5-bis. User-declared cards at pagsusuri ng MyLocalCare",
    },
    "legal.profile_cards_terms_body": {
        "it": "Le schede restano dichiarazioni dell’utente salvo la presenza di uno specifico badge. “Dichiarato dall’utente” indica che MyLocalCare non ha effettuato controlli; “Documento visionato da MyLocalCare” indica soltanto che è stato visionato un documento relativo alla scheda; “Riscontro effettuato da MyLocalCare” indica che una specifica informazione è stata verificata con il metodo registrato. Questi esiti non certificano in modo generale la persona, l’idoneità professionale, l’assenza di rischi o l’abilitazione al lavoro.",
        "en": "Cards remain user declarations unless a specific badge is shown. “Declared by the user” means that MyLocalCare has not performed checks; “Document viewed by MyLocalCare” only means that a document relating to the card was viewed; “Check performed by MyLocalCare” means that specific information was checked using the recorded method. These outcomes do not generally certify the person, professional suitability, absence of risk or eligibility to work.",
        "fr": "Les fiches restent des déclarations de l’utilisateur sauf lorsqu’un badge spécifique est affiché. « Déclaré par l’utilisateur » signifie que MyLocalCare n’a effectué aucun contrôle ; « Document consulté par MyLocalCare » signifie uniquement qu’un document relatif à la fiche a été consulté ; « Vérification effectuée par MyLocalCare » signifie qu’une information précise a été contrôlée selon la méthode enregistrée. Ces résultats ne certifient pas globalement la personne, son aptitude professionnelle, l’absence de risque ou son droit au travail.",
        "es": "Las fichas siguen siendo declaraciones del usuario salvo que se muestre una insignia específica. «Declarado por el usuario» significa que MyLocalCare no ha realizado comprobaciones; «Documento revisado por MyLocalCare» solo significa que se revisó un documento relacionado con la ficha; «Comprobación realizada por MyLocalCare» significa que se comprobó información concreta mediante el método registrado. Estos resultados no certifican en general a la persona, su idoneidad profesional, la ausencia de riesgos ni su autorización para trabajar.",
        "de": "Profilkarten bleiben Angaben des Nutzers, sofern kein bestimmtes Abzeichen angezeigt wird. „Vom Nutzer angegeben“ bedeutet, dass MyLocalCare keine Prüfung vorgenommen hat; „Dokument von MyLocalCare eingesehen“ bedeutet nur, dass ein zur Karte gehörendes Dokument eingesehen wurde; „Prüfung durch MyLocalCare erfolgt“ bedeutet, dass eine bestimmte Angabe mit der dokumentierten Methode geprüft wurde. Diese Ergebnisse bestätigen nicht allgemein die Person, berufliche Eignung, Risikofreiheit oder Arbeitsberechtigung.",
        "ro": "Fișele rămân declarații ale utilizatorului, cu excepția cazului în care este afișată o insignă specifică. „Declarat de utilizator” înseamnă că MyLocalCare nu a efectuat verificări; „Document consultat de MyLocalCare” înseamnă doar că a fost consultat un document referitor la fișă; „Verificare efectuată de MyLocalCare” înseamnă că o anumită informație a fost verificată prin metoda înregistrată. Aceste rezultate nu certifică în general persoana, aptitudinea profesională, lipsa riscurilor sau dreptul de muncă.",
        "uk": "Картки залишаються заявами користувача, якщо не відображено окремий значок. «Заявлено користувачем» означає, що MyLocalCare не проводив перевірку; «Документ переглянуто MyLocalCare» означає лише перегляд документа, що стосується картки; «Перевірку виконано MyLocalCare» означає перевірку конкретної інформації за зафіксованим методом. Ці результати не є загальним підтвердженням особи, професійної придатності, відсутності ризиків чи права на роботу.",
        "fil": "Mananatiling deklarasyon ng user ang mga card maliban kung may partikular na badge. Ang “Declared by the user” ay nangangahulugang walang ginawang pagsusuri ang MyLocalCare; ang “Document viewed by MyLocalCare” ay nangangahulugan lamang na may dokumentong kaugnay ng card na tiningnan; ang “Check performed by MyLocalCare” ay nangangahulugang sinuri ang isang partikular na impormasyon gamit ang naitalang paraan. Hindi nito pangkalahatang pinapatunayan ang tao, professional suitability, kawalan ng panganib, o karapatang magtrabaho.",
    },
    "legal.profile_cards_terms_duty": {
        "it": "La modifica dei dati o la scadenza della qualifica fa decadere il controllo. Chi valuta, incarica o assume una persona deve comunque verificare gli originali, la validità attuale, i requisiti applicabili, le referenze e l’eventuale abilitazione al lavoro prima di concludere un accordo.",
        "en": "Changing the details or expiry of the qualification ends the check. Anyone assessing, engaging or employing a person must still verify originals, current validity, applicable requirements, references and any eligibility to work before making an agreement.",
        "fr": "La modification des données ou l’expiration de la qualification met fin au contrôle. Toute personne qui évalue, mandate ou emploie quelqu’un doit néanmoins vérifier les originaux, la validité actuelle, les exigences applicables, les références et l’éventuel droit au travail avant de conclure un accord.",
        "es": "La modificación de los datos o la caducidad de la cualificación deja sin efecto la comprobación. Quien evalúe, contrate o emplee a una persona debe comprobar igualmente los originales, la validez actual, los requisitos aplicables, las referencias y cualquier autorización para trabajar antes de cerrar un acuerdo.",
        "de": "Eine Änderung der Angaben oder das Ablaufen der Qualifikation beendet die Prüfung. Wer eine Person bewertet, beauftragt oder beschäftigt, muss vor einer Vereinbarung weiterhin Originale, aktuelle Gültigkeit, geltende Anforderungen, Referenzen und eine etwaige Arbeitsberechtigung prüfen.",
        "ro": "Modificarea datelor sau expirarea calificării anulează verificarea. Oricine evaluează, contractează sau angajează o persoană trebuie să verifice în continuare originalele, valabilitatea actuală, cerințele aplicabile, referințele și eventualul drept de muncă înainte de a încheia un acord.",
        "uk": "Зміна даних або завершення строку дії кваліфікації припиняє перевірку. Той, хто оцінює, залучає чи наймає особу, все одно повинен перевірити оригінали, чинність, застосовні вимоги, рекомендації та можливе право на роботу до укладення домовленості.",
        "fil": "Mawawala ang bisa ng pagsusuri kapag binago ang detalye o nag-expire ang qualification. Ang sinumang sumusuri, kumukuha ng serbisyo, o nag-e-employ ng tao ay kailangan pa ring tingnan ang originals, kasalukuyang validity, naaangkop na requirements, references, at karapatang magtrabaho bago gumawa ng kasunduan.",
    },
    "language.open": {
        "it": "Cambia lingua", "en": "Change language", "fr": "Changer de langue",
        "es": "Cambiar idioma", "de": "Sprache ändern",
    },
    "language.title": {
        "it": "Scegli la lingua", "en": "Choose your language", "fr": "Choisissez votre langue",
        "es": "Elige tu idioma", "de": "Sprache auswählen",
    },
    "language.subtitle": {
        "it": "L’interfaccia verrà mostrata nella lingua selezionata.",
        "en": "The interface will be shown in the selected language.",
        "fr": "L’interface sera affichée dans la langue sélectionnée.",
        "es": "La interfaz se mostrará en el idioma seleccionado.",
        "de": "Die Oberfläche wird in der ausgewählten Sprache angezeigt.",
    },
    "language.close": {
        "it": "Chiudi", "en": "Close", "fr": "Fermer", "es": "Cerrar", "de": "Schließen",
    },
    "nav.search_people": {
        "it": "Cerca persone", "en": "Find people", "fr": "Trouver des personnes",
        "es": "Buscar personas", "de": "Personen finden",
    },
    "nav.search_placeholder": {
        "it": "Cerca utenti, digita Username", "en": "Find users by username",
        "fr": "Rechercher par nom d’utilisateur", "es": "Buscar por nombre de usuario",
        "de": "Nach Benutzername suchen",
    },
    "nav.login": {
        "it": "Accedi", "en": "Sign in", "fr": "Se connecter", "es": "Iniciar sesión", "de": "Anmelden",
    },
    "nav.register": {
        "it": "Registrati", "en": "Sign up", "fr": "S’inscrire", "es": "Registrarse", "de": "Registrieren",
    },
    "nav.logout": {
        "it": "Esci", "en": "Sign out", "fr": "Se déconnecter", "es": "Salir", "de": "Abmelden",
    },
    "nav.your_profile": {
        "it": "Il tuo profilo", "en": "Your profile", "fr": "Votre profil",
        "es": "Tu perfil", "de": "Dein Profil",
    },
    "nav.guide": {
        "it": "Guida", "en": "Guide", "fr": "Guide", "es": "Guía", "de": "Hilfe",
    },
    "landing.title": {
        "it": "Il passaparola di una volta, a portata di mano!",
        "en": "Good old word of mouth, now at your fingertips!",
        "fr": "Le bouche-à-oreille d’autrefois, à portée de main !",
        "es": "¡El boca a boca de siempre, al alcance de tu mano!",
        "de": "Gute Empfehlungen aus der Nachbarschaft – direkt zur Hand!",
    },
    "landing.subtitle": {
        "it": "La rete locale dove trovare o offrire aiuto per casa, famiglia, benessere e tempo libero. Più persone partecipano, più il passaparola diventa utile per tutti.",
        "en": "The local network where you can find or offer help for home, family, wellbeing and leisure. The more people join, the more useful it becomes for everyone.",
        "fr": "Le réseau local où trouver ou proposer de l’aide pour la maison, la famille, le bien-être et les loisirs. Plus il grandit, plus il devient utile à tous.",
        "es": "La red local donde encontrar u ofrecer ayuda para el hogar, la familia, el bienestar y el tiempo libre. Cuantas más personas participen, más útil será para todos.",
        "de": "Das lokale Netzwerk, um Hilfe für Zuhause, Familie, Wohlbefinden und Freizeit zu finden oder anzubieten. Je mehr Menschen mitmachen, desto nützlicher wird es für alle.",
    },
    "landing.start": {
        "it": "Da dove vuoi iniziare?", "en": "Where would you like to start?",
        "fr": "Par où souhaitez-vous commencer ?", "es": "¿Por dónde quieres empezar?",
        "de": "Wo möchtest du anfangen?",
    },
    "landing.zone_intro": {
        "it": "Scegli la tua zona per entrare nella rete locale di persone vicino a te.",
        "en": "Choose your area to join the local network of people near you.",
        "fr": "Choisissez votre zone pour rejoindre le réseau local près de chez vous.",
        "es": "Elige tu zona para entrar en la red local de personas cercanas.",
        "de": "Wähle deine Gegend und werde Teil des lokalen Netzwerks in deiner Nähe.",
    },
    "landing.your_zone": {
        "it": "La tua zona", "en": "Your area", "fr": "Votre zone", "es": "Tu zona", "de": "Deine Gegend",
    },
    "landing.zone_placeholder": {
        "it": "Es. Milano, Roma, Torino...", "en": "E.g. Milan, Rome, Turin...",
        "fr": "Ex. Milan, Rome, Turin...", "es": "Ej. Milán, Roma, Turín...", "de": "Z. B. Mailand, Rom, Turin...",
    },
    "common.continue": {
        "it": "Continua", "en": "Continue", "fr": "Continuer", "es": "Continuar", "de": "Weiter",
    },
    "landing.change_zone": {
        "it": "Potrai cambiare zona in qualsiasi momento e scoprire nuove reti locali.",
        "en": "You can change area at any time and discover new local networks.",
        "fr": "Vous pourrez changer de zone à tout moment et découvrir de nouveaux réseaux locaux.",
        "es": "Podrás cambiar de zona en cualquier momento y descubrir nuevas redes locales.",
        "de": "Du kannst deine Gegend jederzeit ändern und neue lokale Netzwerke entdecken.",
    },
    "story.cue": {
        "it": "Scopri cosa puoi fare", "en": "Discover what you can do", "fr": "Découvrez ce que vous pouvez faire",
        "es": "Descubre lo que puedes hacer", "de": "Entdecke deine Möglichkeiten",
    },
    "story.title": {
        "it": "Trova ciò che ti serve. Fatti trovare per ciò che sai fare.",
        "en": "Find what you need. Be found for what you do best.",
        "fr": "Trouvez ce qu’il vous faut. Soyez trouvé pour votre savoir-faire.",
        "es": "Encuentra lo que necesitas. Hazte encontrar por lo que sabes hacer.",
        "de": "Finde, was du brauchst. Werde für dein Können gefunden.",
    },
    "story.intro": {
        "it": "MyLocalCare trasforma il passaparola in una rete locale più chiara: persone, servizi e necessità si incontrano senza perdersi in un feed.",
        "en": "MyLocalCare turns word of mouth into a clearer local network, where people, services and needs meet without getting lost in a feed.",
        "fr": "MyLocalCare transforme le bouche-à-oreille en un réseau local plus clair, où personnes, services et besoins se rencontrent sans se perdre dans un fil.",
        "es": "MyLocalCare convierte el boca a boca en una red local más clara, donde personas, servicios y necesidades se encuentran sin perderse en un feed.",
        "de": "MyLocalCare macht aus Empfehlungen ein übersichtliches lokales Netzwerk, in dem Menschen, Angebote und Bedürfnisse direkt zusammenfinden.",
    },
    "story.seek_offer": {
        "it": "Cerco e Offro", "en": "I need & I offer", "fr": "Je cherche & Je propose",
        "es": "Busco y Ofrezco", "de": "Ich suche & Ich biete",
    },
    "story.two_needs": {
        "it": "Due esigenze. Un’unica rete.", "en": "Two needs. One network.",
        "fr": "Deux besoins. Un seul réseau.", "es": "Dos necesidades. Una sola red.",
        "de": "Zwei Bedürfnisse. Ein Netzwerk.",
    },
    "story.two_needs_text": {
        "it": "Chi cerca incontra persone disponibili. Chi offre trasforma tempo, capacità ed esperienza in una presenza visibile e contattabile.",
        "en": "People looking for help meet people who are available. Those offering help turn their time, skills and experience into a visible, reachable presence.",
        "fr": "Les personnes qui cherchent rencontrent celles qui sont disponibles. Celles qui proposent valorisent leur temps, leurs compétences et leur expérience.",
        "es": "Quien busca encuentra personas disponibles. Quien ofrece convierte su tiempo, habilidades y experiencia en una presencia visible y accesible.",
        "de": "Suchende treffen auf verfügbare Menschen. Anbieter machen Zeit, Fähigkeiten und Erfahrung sichtbar und erreichbar.",
    },
    "story.seek": {"it": "Cerco", "en": "I need", "fr": "Je cherche", "es": "Busco", "de": "Ich suche"},
    "story.offer": {"it": "Offro", "en": "I offer", "fr": "Je propose", "es": "Ofrezco", "de": "Ich biete"},
    "story.seek_text": {
        "it": "Trova persone e servizi coerenti con la tua esigenza e la tua zona.",
        "en": "Find people and services that match your needs and your area.",
        "fr": "Trouvez des personnes et des services adaptés à vos besoins et à votre zone.",
        "es": "Encuentra personas y servicios acordes con tus necesidades y tu zona.",
        "de": "Finde Menschen und Angebote, die zu deinem Bedarf und deiner Gegend passen.",
    },
    "story.offer_text": {
        "it": "Dai valore a ciò che sai fare e fatti trovare da chi ne ha bisogno.",
        "en": "Show the value of your skills and be found by people who need them.",
        "fr": "Valorisez votre savoir-faire et soyez trouvé par ceux qui en ont besoin.",
        "es": "Da valor a lo que sabes hacer y deja que te encuentre quien lo necesita.",
        "de": "Zeige, was du kannst, und werde von Menschen gefunden, die dich brauchen.",
    },
    "story.publish_request": {
        "it": "Se non trovi ciò che cerchi, pubblica la tua richiesta e fatti contattare dalle persone della rete.",
        "en": "If you cannot find what you need, publish your request and let people in the network contact you.",
        "fr": "Si vous ne trouvez pas ce qu’il vous faut, publiez votre demande et laissez le réseau vous contacter.",
        "es": "Si no encuentras lo que buscas, publica tu solicitud y deja que te contacten personas de la red.",
        "de": "Wenn du nicht findest, was du suchst, veröffentliche deine Anfrage und lass dich aus dem Netzwerk kontaktieren.",
    },
    "story.compare": {
        "it": "Confronta annunci e profili per trovare la persona più adatta a te.",
        "en": "Compare listings and profiles to find the right person for you.",
        "fr": "Comparez les annonces et les profils pour trouver la bonne personne.",
        "es": "Compara anuncios y perfiles para encontrar a la persona adecuada.",
        "de": "Vergleiche Anzeigen und Profile, um die passende Person zu finden.",
    },
    "story.personal_space": {
        "it": "Il tuo spazio personale", "en": "Your personal space", "fr": "Votre espace personnel",
        "es": "Tu espacio personal", "de": "Dein persönlicher Bereich",
    },
    "story.not_just_name": {
        "it": "Non sei soltanto un nome sotto un post.", "en": "You are more than a name under a post.",
        "fr": "Vous êtes bien plus qu’un nom sous une publication.", "es": "Eres mucho más que un nombre bajo una publicación.",
        "de": "Du bist mehr als nur ein Name unter einem Beitrag.",
    },
    "story.profile_text": {
        "it": "Un profilo completo racconta chi sei e rende immediatamente più chiaro perché una persona dovrebbe scegliere proprio te.",
        "en": "A complete profile tells people who you are and makes it clear why they should choose you.",
        "fr": "Un profil complet raconte qui vous êtes et montre clairement pourquoi on devrait vous choisir.",
        "es": "Un perfil completo cuenta quién eres y deja claro por qué deberían elegirte.",
        "de": "Ein vollständiges Profil zeigt, wer du bist und warum man sich für dich entscheiden sollte.",
    },
    "story.present_yourself": {
        "it": "Presentati davvero", "en": "Show who you are", "fr": "Présentez-vous vraiment",
        "es": "Preséntate de verdad", "de": "Zeige, wer du bist",
    },
    "story.present_yourself_text": {
        "it": "Foto, descrizione e ciò che ti distingue.", "en": "Photos, a description and what makes you unique.",
        "fr": "Photos, description et ce qui vous distingue.", "es": "Fotos, descripción y lo que te diferencia.",
        "de": "Fotos, Beschreibung und das, was dich auszeichnet.",
    },
    "story.show_value": {
        "it": "Rendi visibile il tuo valore", "en": "Make your value visible", "fr": "Montrez votre valeur",
        "es": "Haz visible tu valor", "de": "Mach deinen Wert sichtbar",
    },
    "story.show_value_text": {
        "it": "Esperienze, competenze, lingue e servizi.", "en": "Experience, skills, languages and services.",
        "fr": "Expériences, compétences, langues et services.", "es": "Experiencia, habilidades, idiomas y servicios.",
        "de": "Erfahrung, Fähigkeiten, Sprachen und Angebote.",
    },
    "story.build_trust": {
        "it": "Costruisci fiducia", "en": "Build trust", "fr": "Inspirez confiance",
        "es": "Genera confianza", "de": "Baue Vertrauen auf",
    },
    "story.build_trust_text": {
        "it": "Informazioni chiare, foto e recensioni in un solo posto.",
        "en": "Clear information, photos and reviews in one place.",
        "fr": "Informations claires, photos et avis au même endroit.",
        "es": "Información clara, fotos y reseñas en un solo lugar.",
        "de": "Klare Informationen, Fotos und Bewertungen an einem Ort.",
    },
    "story.opportunities": {
        "it": "Le opportunità non si perdono", "en": "Opportunities do not get lost",
        "fr": "Les opportunités ne se perdent pas", "es": "Las oportunidades no se pierden",
        "de": "Keine Chance geht verloren",
    },
    "story.notifications": {"it": "Notifiche", "en": "Notifications", "fr": "Notifications", "es": "Notificaciones", "de": "Benachrichtigungen"},
    "story.notifications_text": {
        "it": "Sai quando c’è qualcosa che merita la tua attenzione.",
        "en": "You know when something deserves your attention.",
        "fr": "Vous savez quand quelque chose mérite votre attention.",
        "es": "Sabes cuándo algo merece tu atención.",
        "de": "Du erfährst, wenn etwas deine Aufmerksamkeit verdient.",
    },
    "story.messages": {"it": "Messaggi", "en": "Messages", "fr": "Messages", "es": "Mensajes", "de": "Nachrichten"},
    "story.messages_text": {
        "it": "Parli direttamente con la persona interessata, nello stesso spazio.",
        "en": "Talk directly to the interested person in the same place.",
        "fr": "Échangez directement avec la personne intéressée, au même endroit.",
        "es": "Habla directamente con la persona interesada en el mismo espacio.",
        "de": "Sprich direkt mit der interessierten Person – am selben Ort.",
    },
    "story.clear_intent": {"it": "Intenzioni chiare", "en": "Clear intentions", "fr": "Intentions claires", "es": "Intenciones claras", "de": "Klare Absichten"},
    "story.clear_intent_text": {
        "it": "Cerco e Offro fanno capire subito che tipo di contatto desideri.",
        "en": "I need and I offer make the kind of contact you want immediately clear.",
        "fr": "Je cherche et Je propose indiquent immédiatement le type de contact souhaité.",
        "es": "Busco y Ofrezco dejan claro de inmediato qué tipo de contacto deseas.",
        "de": "Ich suche und Ich biete zeigen sofort, welche Art von Kontakt du wünschst.",
    },
    "story.community": {
        "it": "La community prende forma", "en": "The community takes shape", "fr": "La communauté prend forme",
        "es": "La comunidad toma forma", "de": "Die Community nimmt Gestalt an",
    },
    "story.categories_title": {
        "it": "I servizi più richiesti. E nuove possibilità da far crescere.",
        "en": "The most requested services, and new opportunities to grow.",
        "fr": "Les services les plus demandés et de nouvelles possibilités à développer.",
        "es": "Los servicios más solicitados y nuevas posibilidades por desarrollar.",
        "de": "Die gefragtesten Angebote und neue Möglichkeiten mit Potenzial.",
    },
    "story.categories_text": {
        "it": "Casa, famiglia, animali, studio e benessere convivono nella stessa rete: ogni persona può trovare ciò che cerca e dare spazio a ciò che offre.",
        "en": "Home, family, pets, education and wellbeing live in the same network: everyone can find what they need and showcase what they offer.",
        "fr": "Maison, famille, animaux, études et bien-être coexistent dans le même réseau : chacun peut trouver ce qu’il cherche et valoriser ce qu’il propose.",
        "es": "Hogar, familia, mascotas, estudios y bienestar conviven en la misma red: todos pueden encontrar lo que buscan y mostrar lo que ofrecen.",
        "de": "Haushalt, Familie, Tiere, Lernen und Wohlbefinden finden im selben Netzwerk Platz: Jeder kann finden, was er sucht, und zeigen, was er anbietet.",
    },
    "story.babysitter_text": {
        "it": "Persone e famiglie possono incontrarsi nella stessa zona.", "en": "People and families can meet in the same area.",
        "fr": "Personnes et familles peuvent se rencontrer dans la même zone.", "es": "Personas y familias pueden encontrarse en la misma zona.",
        "de": "Menschen und Familien können sich in derselben Gegend finden.",
    },
    "story.pet_text": {
        "it": "Supporto fidato per cani, gatti e altri animali domestici.", "en": "Trusted support for dogs, cats and other pets.",
        "fr": "Une aide de confiance pour chiens, chats et autres animaux.", "es": "Ayuda de confianza para perros, gatos y otras mascotas.",
        "de": "Vertrauensvolle Betreuung für Hunde, Katzen und andere Haustiere.",
    },
    "story.home_help": {"it": "Aiuto in casa", "en": "Home help", "fr": "Aide à domicile", "es": "Ayuda en casa", "de": "Hilfe im Haushalt"},
    "story.home_help_text": {
        "it": "Collaborazioni per pulizie, spesa, stiro e necessità quotidiane.", "en": "Help with cleaning, shopping, ironing and everyday needs.",
        "fr": "Aide pour le ménage, les courses, le repassage et les besoins quotidiens.", "es": "Ayuda con limpieza, compras, plancha y necesidades cotidianas.",
        "de": "Unterstützung bei Reinigung, Einkäufen, Bügeln und im Alltag.",
    },
    "story.tutoring": {"it": "Ripetizioni", "en": "Tutoring", "fr": "Soutien scolaire", "es": "Clases particulares", "de": "Nachhilfe"},
    "story.tutoring_text": {
        "it": "Lezioni e sostegno scolastico, vicino a te oppure online.", "en": "Lessons and study support near you or online.",
        "fr": "Cours et soutien scolaire près de chez vous ou en ligne.", "es": "Clases y apoyo escolar cerca de ti o en línea.",
        "de": "Unterricht und Lernunterstützung in deiner Nähe oder online.",
    },
    "story.new_opportunity": {"it": "Nuova opportunità", "en": "New opportunity", "fr": "Nouvelle opportunité", "es": "Nueva oportunidad", "de": "Neue Chance"},
    "story.wellbeing": {"it": "Benessere & Personal Trainer", "en": "Wellbeing & Personal Training", "fr": "Bien-être & Coaching sportif", "es": "Bienestar y entrenamiento personal", "de": "Wellness & Personal Training"},
    "story.wellbeing_text": {
        "it": "Una vetrina personale per professionisti che vogliono farsi conoscere in una rete locale già interessata alla cura e alla qualità della vita.",
        "en": "A personal showcase for professionals who want to be known in a local network already interested in care and quality of life.",
        "fr": "Une vitrine personnelle pour les professionnels qui souhaitent se faire connaître auprès d’un réseau local sensible au bien-être et à la qualité de vie.",
        "es": "Un escaparate personal para profesionales que quieren darse a conocer en una red local interesada en el cuidado y la calidad de vida.",
        "de": "Eine persönliche Bühne für Fachleute, die in einem lokalen Netzwerk rund um Fürsorge und Lebensqualität sichtbar werden möchten.",
    },
    "story.wellbeing_note": {
        "it": "Uno spazio nuovo in cui distinguersi.", "en": "A new space where you can stand out.",
        "fr": "Un nouvel espace pour vous démarquer.", "es": "Un nuevo espacio donde destacar.",
        "de": "Ein neuer Ort, an dem du dich abheben kannst.",
    },
    "story.free_signup": {"it": "Iscrizione gratuita", "en": "Free registration", "fr": "Inscription gratuite", "es": "Registro gratuito", "de": "Kostenlose Anmeldung"},
    "story.final_title": {
        "it": "La persona giusta potrebbe essere già nella tua rete.",
        "en": "The right person may already be in your network.",
        "fr": "La bonne personne est peut-être déjà dans votre réseau.",
        "es": "La persona adecuada quizá ya esté en tu red.",
        "de": "Die richtige Person ist vielleicht schon in deinem Netzwerk.",
    },
    "story.final_text": {
        "it": "Crea il tuo profilo, pubblica ciò che cerchi o offri e diventa parte di un passaparola locale che cresce insieme alle persone.",
        "en": "Create your profile, publish what you need or offer, and join a local word-of-mouth network that grows with its people.",
        "fr": "Créez votre profil, publiez ce que vous cherchez ou proposez et rejoignez un réseau local qui grandit avec ses membres.",
        "es": "Crea tu perfil, publica lo que buscas u ofreces y forma parte de una red local que crece con las personas.",
        "de": "Erstelle dein Profil, veröffentliche, was du suchst oder anbietest, und werde Teil eines lokalen Netzwerks, das mit seinen Menschen wächst.",
    },
    "story.register_free": {"it": "Registrati gratis", "en": "Sign up free", "fr": "Inscrivez-vous gratuitement", "es": "Regístrate gratis", "de": "Kostenlos registrieren"},
    "story.explore_zone": {"it": "Esplora la tua zona", "en": "Explore your area", "fr": "Explorez votre zone", "es": "Explora tu zona", "de": "Entdecke deine Gegend"},
    "story.explore_guest": {
        "it": "Puoi esplorare gli annunci della tua zona anche prima di registrarti.",
        "en": "You can explore listings in your area even before signing up.",
        "fr": "Vous pouvez explorer les annonces de votre zone avant même de vous inscrire.",
        "es": "Puedes explorar los anuncios de tu zona incluso antes de registrarte.",
        "de": "Du kannst Anzeigen in deiner Gegend schon vor der Registrierung ansehen.",
    },
    "profile.settings": {"it": "Impostazioni", "en": "Settings", "fr": "Paramètres", "es": "Ajustes", "de": "Einstellungen"},
    "profile.announcements": {"it": "Annunci", "en": "Listings", "fr": "Annonces", "es": "Anuncios", "de": "Anzeigen"},
    "profile.info": {"it": "Info", "en": "Info", "fr": "Infos", "es": "Info", "de": "Info"},
    "profile.photos": {"it": "Foto", "en": "Photos", "fr": "Photos", "es": "Fotos", "de": "Fotos"},
    "profile.reviews": {"it": "Recensioni", "en": "Reviews", "fr": "Avis", "es": "Reseñas", "de": "Bewertungen"},
    "profile.write_chat": {"it": "Scrivi in chat", "en": "Send a message", "fr": "Écrire un message", "es": "Escribir por chat", "de": "Nachricht schreiben"},
    "profile.create_listing": {"it": "Crea annuncio", "en": "Create listing", "fr": "Créer une annonce", "es": "Crear anuncio", "de": "Anzeige erstellen"},
    "profile.gallery": {"it": "Galleria personale", "en": "Personal gallery", "fr": "Galerie personnelle", "es": "Galería personal", "de": "Persönliche Galerie"},
    "profile.no_photos": {"it": "Nessuna foto disponibile.", "en": "No photos available.", "fr": "Aucune photo disponible.", "es": "No hay fotos disponibles.", "de": "Keine Fotos verfügbar."},
    "gallery.safe_photos": {
        "it": "Foto profilo sicure", "en": "Safe profile photos", "fr": "Photos de profil sécurisées",
        "es": "Fotos de perfil seguras", "de": "Sichere Profilfotos",
    },
    "gallery.no_contacts_title": {
        "it": "Non inserire contatti nelle immagini", "en": "Do not include contact details in images",
        "fr": "N’ajoutez pas de coordonnées dans les images", "es": "No incluyas datos de contacto en las imágenes",
        "de": "Keine Kontaktdaten in Bildern einfügen",
    },
    "gallery.no_contacts_body": {
        "it": "Le foto della galleria servono per presentarti meglio, ma non devono contenere numeri di telefono, email, WhatsApp, profili social, QR code o altri recapiti diretti.",
        "en": "Gallery photos help you introduce yourself, but they must not contain phone numbers, email addresses, WhatsApp details, social profiles, QR codes or other direct contact details.",
        "fr": "Les photos de la galerie vous aident à vous présenter, mais elles ne doivent contenir ni numéro de téléphone, ni adresse e-mail, ni coordonnées WhatsApp, ni profil social, ni code QR, ni autre moyen de contact direct.",
        "es": "Las fotos de la galería sirven para presentarte mejor, pero no deben contener números de teléfono, correos electrónicos, datos de WhatsApp, perfiles sociales, códigos QR ni otros datos de contacto directo.",
        "de": "Galeriefotos helfen dir, dich besser vorzustellen. Sie dürfen jedoch keine Telefonnummern, E-Mail-Adressen, WhatsApp-Daten, Social-Media-Profile, QR-Codes oder andere direkte Kontaktdaten enthalten.",
    },
    "gallery.contacts_section": {
        "it": "Per i contatti esiste una sezione dedicata del profilo.",
        "en": "Use the dedicated profile section for contact details.",
        "fr": "Utilisez la section dédiée du profil pour vos coordonnées.",
        "es": "Utiliza la sección específica del perfil para los datos de contacto.",
        "de": "Nutze für Kontaktdaten den dafür vorgesehenen Profilbereich.",
    },
    "gallery.review_notice": {
        "it": "Le immagini caricate vengono verificate prima della pubblicazione. Se contengono recapiti o informazioni non adatte, potrebbero non essere approvate.",
        "en": "Uploaded images are reviewed before publication. Images containing contact details or unsuitable information may not be approved.",
        "fr": "Les images importées sont vérifiées avant publication. Celles qui contiennent des coordonnées ou des informations inappropriées peuvent être refusées.",
        "es": "Las imágenes subidas se revisan antes de publicarse. Si contienen datos de contacto o información inadecuada, podrían no aprobarse.",
        "de": "Hochgeladene Bilder werden vor der Veröffentlichung geprüft. Bilder mit Kontaktdaten oder ungeeigneten Informationen werden möglicherweise nicht freigegeben.",
    },
    "gallery.uploading": {
        "it": "Caricamento foto in corso... Attendi senza chiudere la pagina.",
        "en": "Uploading photos... Please wait without closing the page.",
        "fr": "Importation des photos... Patientez sans fermer la page.",
        "es": "Subiendo fotos... Espera sin cerrar la página.",
        "de": "Fotos werden hochgeladen... Bitte die Seite nicht schließen.",
    },
    "gallery.delete_hint": {
        "it": "Per eliminare una foto, premi Elimina sulla foto interessata.",
        "en": "To remove a photo, select Delete on that photo.",
        "fr": "Pour supprimer une photo, appuyez sur Supprimer sur la photo concernée.",
        "es": "Para eliminar una foto, pulsa Eliminar en la foto correspondiente.",
        "de": "Um ein Foto zu entfernen, wähle beim entsprechenden Foto Löschen.",
    },
    "gallery.empty": {
        "it": "Nessuna foto in galleria.", "en": "No photos in your gallery.", "fr": "Aucune photo dans votre galerie.",
        "es": "No hay fotos en tu galería.", "de": "Keine Fotos in deiner Galerie.",
    },
    "gallery.add_photos": {
        "it": "Aggiungi foto (massimo 4)", "en": "Add photos (up to 4)", "fr": "Ajouter des photos (4 maximum)",
        "es": "Añadir fotos (máximo 4)", "de": "Fotos hinzufügen (maximal 4)",
    },
    "gallery.operation_running": {
        "it": "Operazione in corso... Attendi senza chiudere la pagina.",
        "en": "Operation in progress... Please wait without closing the page.",
        "fr": "Opération en cours... Patientez sans fermer la page.",
        "es": "Operación en curso... Espera sin cerrar la página.",
        "de": "Vorgang läuft... Bitte die Seite nicht schließen.",
    },
    "gallery.operation_already_running": {
        "it": "È già in corso un'operazione. Attendi il completamento.",
        "en": "An operation is already in progress. Wait for it to finish.",
        "fr": "Une opération est déjà en cours. Attendez qu’elle se termine.",
        "es": "Ya hay una operación en curso. Espera a que termine.",
        "de": "Ein Vorgang läuft bereits. Warte, bis er abgeschlossen ist.",
    },
    "gallery.delete_confirm": {
        "it": "Vuoi eliminare questa foto dalla galleria?", "en": "Delete this photo from the gallery?",
        "fr": "Supprimer cette photo de la galerie ?", "es": "¿Eliminar esta foto de la galería?",
        "de": "Dieses Foto aus der Galerie löschen?",
    },
    "gallery.upload_running_short": {
        "it": "È già in corso un caricamento. Attendi qualche secondo.",
        "en": "An upload is already in progress. Wait a few seconds.",
        "fr": "Un import est déjà en cours. Patientez quelques secondes.",
        "es": "Ya hay una carga en curso. Espera unos segundos.",
        "de": "Ein Upload läuft bereits. Warte einige Sekunden.",
    },
    "gallery.upload_running": {
        "it": "È già in corso un caricamento. Attendi il completamento.",
        "en": "An upload is already in progress. Wait for it to finish.",
        "fr": "Un import est déjà en cours. Attendez qu’il se termine.",
        "es": "Ya hay una carga en curso. Espera a que termine.",
        "de": "Ein Upload läuft bereits. Warte, bis er abgeschlossen ist.",
    },
    "gallery.limit_reached": {
        "it": "Hai raggiunto il limite massimo di 4 foto.", "en": "You have reached the 4-photo limit.",
        "fr": "Vous avez atteint la limite de 4 photos.", "es": "Has alcanzado el límite de 4 fotos.",
        "de": "Du hast das Limit von 4 Fotos erreicht.",
    },
    "gallery.delete_before_adding": {
        "it": "Per aggiungerne di nuove, elimina prima una foto.",
        "en": "Delete a photo before adding a new one.",
        "fr": "Supprimez une photo avant d’en ajouter une autre.",
        "es": "Elimina una foto antes de añadir otra.",
        "de": "Lösche zuerst ein Foto, bevor du ein neues hinzufügst.",
    },
    "gallery.maximum_four": {
        "it": "Puoi avere massimo 4 foto in galleria.", "en": "You can have up to 4 photos in your gallery.",
        "fr": "Vous pouvez avoir au maximum 4 photos dans votre galerie.",
        "es": "Puedes tener un máximo de 4 fotos en tu galería.",
        "de": "Du kannst maximal 4 Fotos in deiner Galerie haben.",
    },
    "gallery.current_count": {
        "it": "Foto attuali: {count}.", "en": "Current photos: {count}.", "fr": "Photos actuelles : {count}.",
        "es": "Fotos actuales: {count}.", "de": "Aktuelle Fotos: {count}.",
    },
    "register.title": {"it": "Crea un account", "en": "Create an account", "fr": "Créer un compte", "es": "Crear una cuenta", "de": "Konto erstellen"},
    "register.language_hint": {
        "it": "Lingua della registrazione", "en": "Registration language", "fr": "Langue d’inscription",
        "es": "Idioma del registro", "de": "Sprache der Registrierung",
    },
    "register.first_name": {"it": "Nome", "en": "First name", "fr": "Prénom", "es": "Nombre", "de": "Vorname"},
    "register.last_name": {"it": "Cognome", "en": "Last name", "fr": "Nom", "es": "Apellidos", "de": "Nachname"},
    "register.city": {"it": "Città / Comune", "en": "City / Municipality", "fr": "Ville / Commune", "es": "Ciudad / Municipio", "de": "Stadt / Gemeinde"},
    "register.city_placeholder": {"it": "Es. Milano", "en": "E.g. Milan", "fr": "Ex. Milan", "es": "Ej. Milán", "de": "Z. B. Mailand"},
    "register.email": {"it": "Email", "en": "Email", "fr": "E-mail", "es": "Correo electrónico", "de": "E-Mail"},
    "register.user_id": {"it": "ID utente (nome pubblico)", "en": "User ID (public name)", "fr": "Identifiant (nom public)", "es": "ID de usuario (nombre público)", "de": "Benutzer-ID (öffentlicher Name)"},
    "register.password": {"it": "Password", "en": "Password", "fr": "Mot de passe", "es": "Contraseña", "de": "Passwort"},
    "register.password_title": {
        "it": "La password deve avere almeno 8 caratteri, almeno una lettera e almeno un numero.",
        "en": "The password must be at least 8 characters long and include at least one letter and one number.",
        "fr": "Le mot de passe doit contenir au moins 8 caractères, une lettre et un chiffre.",
        "es": "La contraseña debe tener al menos 8 caracteres, una letra y un número.",
        "de": "Das Passwort muss mindestens 8 Zeichen, einen Buchstaben und eine Zahl enthalten.",
    },
    "register.password_hint": {
        "it": "Minimo 8 caratteri, almeno una lettera e un numero.",
        "en": "At least 8 characters, including one letter and one number.",
        "fr": "Au moins 8 caractères, dont une lettre et un chiffre.",
        "es": "Mínimo 8 caracteres, con al menos una letra y un número.",
        "de": "Mindestens 8 Zeichen, darunter ein Buchstabe und eine Zahl.",
    },
    "register.confirm_password": {"it": "Conferma password", "en": "Confirm password", "fr": "Confirmer le mot de passe", "es": "Confirmar contraseña", "de": "Passwort bestätigen"},
    "register.consent_intro": {
        "it": "Dichiaro di aver letto e compreso i documenti indicati e accetto le condizioni applicabili:",
        "en": "I confirm that I have read and understood the documents below and accept the applicable terms:",
        "fr": "Je confirme avoir lu et compris les documents ci-dessous et accepter les conditions applicables :",
        "es": "Declaro que he leído y comprendido los documentos indicados y acepto las condiciones aplicables:",
        "de": "Ich bestätige, dass ich die folgenden Dokumente gelesen und verstanden habe und die geltenden Bedingungen akzeptiere:",
    },
    "register.privacy": {"it": "Informativa sulla Privacy", "en": "Privacy Policy", "fr": "Politique de confidentialité", "es": "Política de privacidad", "de": "Datenschutzerklärung"},
    "register.cookie": {"it": "Cookie Policy", "en": "Cookie Policy", "fr": "Politique relative aux cookies", "es": "Política de cookies", "de": "Cookie-Richtlinie"},
    "register.terms": {"it": "Termini e Condizioni", "en": "Terms and Conditions", "fr": "Conditions générales", "es": "Términos y condiciones", "de": "Allgemeine Geschäftsbedingungen"},
    "register.legal_note": {
        "it": "Le traduzioni sono di cortesia. In caso di discrepanze prevale il testo ufficiale italiano.",
        "en": "Courtesy translations are provided. In case of discrepancies, the official Italian text prevails.",
        "fr": "Des traductions de courtoisie sont fournies. En cas de divergence, le texte officiel italien prévaut.",
        "es": "Se ofrecen traducciones de cortesía. En caso de discrepancia, prevalece el texto oficial italiano.",
        "de": "Es werden unverbindliche Übersetzungen bereitgestellt. Bei Abweichungen ist der offizielle italienische Text maßgeblich.",
        "ro": "Sunt oferite traduceri de curtoazie. În caz de neconcordanțe, prevalează textul oficial în limba italiană.",
        "uk": "Надано неофіційні переклади. У разі розбіжностей переважну силу має офіційний текст італійською мовою.",
        "fil": "May mga pagsasalin para sa kaginhawaan. Kung may pagkakaiba, mananaig ang opisyal na tekstong Italyano.",
    },
    "register.submit": {"it": "Registrati", "en": "Sign up", "fr": "S’inscrire", "es": "Registrarse", "de": "Registrieren"},
    "register.show_password": {"it": "Mostra password", "en": "Show password", "fr": "Afficher le mot de passe", "es": "Mostrar contraseña", "de": "Passwort anzeigen"},
    "register.hide_password": {"it": "Nascondi password", "en": "Hide password", "fr": "Masquer le mot de passe", "es": "Ocultar contraseña", "de": "Passwort ausblenden"},
    "register.email_bad_format": {"it": "L’indirizzo email sembra avere un formato non corretto.", "en": "The email address format appears to be incorrect.", "fr": "Le format de l’adresse e-mail semble incorrect.", "es": "El formato del correo parece incorrecto.", "de": "Das Format der E-Mail-Adresse scheint ungültig zu sein."},
    "register.email_missing_domain": {"it": "Controlla bene l’indirizzo email: sembra mancare una parte del dominio.", "en": "Check the email address: part of the domain appears to be missing.", "fr": "Vérifiez l’adresse e-mail : une partie du domaine semble manquer.", "es": "Comprueba el correo: parece faltar parte del dominio.", "de": "Prüfe die E-Mail-Adresse: Ein Teil der Domain scheint zu fehlen."},
    "register.email_unusual_domain": {"it": "Il dominio dell’email sembra insolito. Controlla bene prima di continuare.", "en": "The email domain looks unusual. Check it before continuing.", "fr": "Le domaine de l’e-mail semble inhabituel. Vérifiez-le avant de continuer.", "es": "El dominio del correo parece inusual. Compruébalo antes de continuar.", "de": "Die E-Mail-Domain wirkt ungewöhnlich. Prüfe sie vor dem Fortfahren."},
    "register.email_possible_error": {"it": "L’indirizzo email potrebbe contenere un errore.", "en": "The email address may contain an error.", "fr": "L’adresse e-mail contient peut-être une erreur.", "es": "El correo electrónico podría contener un error.", "de": "Die E-Mail-Adresse enthält möglicherweise einen Fehler."},
    "register.maybe_meant": {"it": "Forse intendevi", "en": "Did you mean", "fr": "Vouliez-vous dire", "es": "Quizá querías decir", "de": "Meintest du"},
    "register.email_confirmation_warning": {"it": "Se l’email è sbagliata non riceverai il link di conferma.", "en": "If the email is incorrect, you will not receive the confirmation link.", "fr": "Si l’adresse e-mail est incorrecte, vous ne recevrez pas le lien de confirmation.", "es": "Si el correo es incorrecto, no recibirás el enlace de confirmación.", "de": "Wenn die E-Mail-Adresse falsch ist, erhältst du den Bestätigungslink nicht."},
    "register.check_email": {"it": "Controlla bene l’indirizzo email.", "en": "Check the email address carefully.", "fr": "Vérifiez attentivement l’adresse e-mail.", "es": "Comprueba bien el correo electrónico.", "de": "Prüfe die E-Mail-Adresse sorgfältig."},
    "register.password_mismatch": {"it": "Le password non coincidono.", "en": "Passwords do not match.", "fr": "Les mots de passe ne correspondent pas.", "es": "Las contraseñas no coinciden.", "de": "Die Passwörter stimmen nicht überein."},
    "register.email_entered_may_error": {"it": "L’indirizzo email inserito potrebbe contenere un errore.", "en": "The email address you entered may contain an error.", "fr": "L’adresse e-mail saisie contient peut-être une erreur.", "es": "El correo electrónico introducido podría contener un error.", "de": "Die eingegebene E-Mail-Adresse enthält möglicherweise einen Fehler."},
    "register.you_entered": {"it": "Hai scritto:", "en": "You entered:", "fr": "Vous avez saisi :", "es": "Has escrito:", "de": "Du hast eingegeben:"},
    "register.maybe_meant_label": {"it": "Forse intendevi:", "en": "Did you mean:", "fr": "Vouliez-vous dire :", "es": "Quizá querías decir:", "de": "Meintest du:"},
    "register.continue_with_email": {"it": "Vuoi continuare comunque con l’email inserita?", "en": "Do you still want to continue with the email you entered?", "fr": "Voulez-vous tout de même continuer avec l’adresse e-mail saisie ?", "es": "¿Quieres continuar de todos modos con el correo introducido?", "de": "Möchtest du trotzdem mit der eingegebenen E-Mail-Adresse fortfahren?"},
    "register.check_email_label": {"it": "Controlla bene l’indirizzo email:", "en": "Check the email address carefully:", "fr": "Vérifiez attentivement l’adresse e-mail :", "es": "Comprueba bien el correo electrónico:", "de": "Prüfe die E-Mail-Adresse sorgfältig:"},
    "register.email_wrong_short": {"it": "Se è sbagliato non riceverai il link di conferma.", "en": "If it is incorrect, you will not receive the confirmation link.", "fr": "Si elle est incorrecte, vous ne recevrez pas le lien de confirmation.", "es": "Si es incorrecto, no recibirás el enlace de confirmación.", "de": "Wenn sie falsch ist, erhältst du den Bestätigungslink nicht."},
    "register.continue_anyway": {"it": "Vuoi continuare comunque?", "en": "Do you still want to continue?", "fr": "Voulez-vous tout de même continuer ?", "es": "¿Quieres continuar de todos modos?", "de": "Möchtest du trotzdem fortfahren?"},
    "search.my_interests": {
        "it": "I miei interessi", "en": "My interests", "fr": "Mes favoris",
        "es": "Mis intereses", "de": "Meine Interessen",
    },
    "profile.contacts.title": {
        "it": "Contatti e presenza online",
        "en": "Contacts and online presence",
        "fr": "Contacts et présence en ligne",
        "es": "Contactos y presencia online",
        "de": "Kontaktdaten und Online-Präsenz",
        "ro": "Contacte și prezență online",
        "uk": "Контакти та присутність онлайн",
        "fil": "Mga contact at online presence",
    },
    "profile.contacts.subtitle": {
        "it": "Inserisci i riferimenti utili per farti contattare e trovarti online.",
        "en": "Add useful details so people can contact and find you online.",
        "fr": "Ajoutez les informations utiles pour être contacté et trouvé en ligne.",
        "es": "Añade datos útiles para que puedan contactarte y encontrarte online.",
        "de": "Füge Angaben hinzu, über die man dich kontaktieren und online finden kann.",
        "ro": "Adaugă informații utile pentru a putea fi contactat și găsit online.",
        "uk": "Додайте корисні дані, щоб з вами могли зв’язатися та знайти вас онлайн.",
        "fil": "Magdagdag ng impormasyon para makontak at mahanap ka online.",
    },
    "profile.contacts.visibility_note": {
        "it": "I contatti saranno visibili solo con almeno un annuncio pubblicato e il servizio Contatti attivo in Aumenta visibilità. In alternativa, gli utenti possono scriverti gratis in chat.",
        "en": "Your contact details are visible only when you have at least one published listing and the Contacts service is active under Boost visibility. Users can always message you in chat for free.",
        "fr": "Vos coordonnées ne sont visibles qu’avec au moins une annonce publiée et le service Contacts activé dans Booster la visibilité. Les utilisateurs peuvent toujours vous écrire gratuitement dans le chat.",
        "es": "Tus datos de contacto solo serán visibles si tienes al menos un anuncio publicado y el servicio Contactos está activo en Aumentar visibilidad. Los usuarios siempre pueden escribirte gratis por chat.",
        "de": "Deine Kontaktdaten sind nur sichtbar, wenn mindestens eine Anzeige veröffentlicht und der Dienst Kontakte unter Sichtbarkeit erhöhen aktiv ist. Nutzer können dir jederzeit kostenlos im Chat schreiben.",
        "ro": "Datele tale de contact sunt vizibile numai dacă ai cel puțin un anunț publicat și serviciul Contacte este activ în Crește vizibilitatea. Utilizatorii îți pot scrie oricând gratuit în chat.",
        "uk": "Ваші контактні дані видно лише за наявності щонайменше одного опублікованого оголошення та активної послуги «Контакти» в розділі підвищення видимості. Користувачі завжди можуть безкоштовно написати вам у чаті.",
        "fil": "Makikita lamang ang iyong contact details kapag may hindi bababa sa isang naka-publish na listing at aktibo ang Contacts service sa Boost visibility. Maaari ka pa ring i-message ng mga user nang libre sa chat.",
    },
    "profile.contacts.no_public_references": {
        "it": "Questo utente non ha ancora inserito riferimenti pubblici.",
        "en": "This user has not added any public contact details yet.",
        "fr": "Cet utilisateur n’a pas encore ajouté de coordonnées publiques.",
        "es": "Este usuario aún no ha añadido datos de contacto públicos.",
        "de": "Dieser Nutzer hat noch keine öffentlichen Kontaktdaten hinzugefügt.",
        "ro": "Acest utilizator nu a adăugat încă date de contact publice.",
        "uk": "Цей користувач ще не додав публічних контактних даних.",
        "fil": "Wala pang idinagdag na pampublikong contact details ang user na ito.",
    },
    "upload.choose_file": {
        "it": "Scegli file", "en": "Choose file", "fr": "Choisir un fichier",
        "es": "Elegir archivo", "de": "Datei auswählen", "ro": "Alege fișierul",
        "uk": "Вибрати файл", "fil": "Pumili ng file",
    },
    "upload.choose_files": {
        "it": "Scegli file", "en": "Choose files", "fr": "Choisir des fichiers",
        "es": "Elegir archivos", "de": "Dateien auswählen", "ro": "Alege fișiere",
        "uk": "Вибрати файли", "fil": "Pumili ng mga file",
    },
    "upload.no_file": {
        "it": "Nessun file selezionato", "en": "No file selected", "fr": "Aucun fichier sélectionné",
        "es": "Ningún archivo seleccionado", "de": "Keine Datei ausgewählt", "ro": "Niciun fișier selectat",
        "uk": "Файл не вибрано", "fil": "Walang napiling file",
    },
    "upload.files_selected": {
        "it": "{count} file selezionati", "en": "{count} files selected", "fr": "{count} fichiers sélectionnés",
        "es": "{count} archivos seleccionados", "de": "{count} Dateien ausgewählt", "ro": "{count} fișiere selectate",
        "uk": "Вибрано файлів: {count}", "fil": "{count} file ang napili",
    },
    "home.category.home_help": {
        "it": "Aiuto in Casa", "en": "Home help", "fr": "Aide à domicile",
        "es": "Ayuda en casa", "de": "Hilfe im Haushalt", "ro": "Ajutor acasă",
        "uk": "Допомога вдома", "fil": "Tulong sa bahay",
    },
    "home.category.babysitter_description": {
        "it": "Servizi affidabili per la cura dei più piccoli, anche occasionali.",
        "en": "Trusted childcare services, including occasional help.",
        "fr": "Services de garde fiables pour les plus petits, même ponctuellement.",
        "es": "Servicios fiables para cuidar a los más pequeños, también de forma ocasional.",
        "de": "Zuverlässige Betreuung für Kinder, auch gelegentlich.",
        "ro": "Servicii de încredere pentru îngrijirea copiilor, inclusiv ocazional.",
        "uk": "Надійні послуги догляду за дітьми, зокрема час від часу.",
        "fil": "Maaasahang pag-aalaga ng mga bata, kahit paminsan-minsan.",
    },
    "home.category.home_help_description": {
        "it": "Pulizie, spesa, stiro, babysitting occasionale e altro.",
        "en": "Cleaning, shopping, ironing, occasional babysitting and more.",
        "fr": "Ménage, courses, repassage, garde occasionnelle et plus encore.",
        "es": "Limpieza, compras, plancha, cuidado infantil ocasional y más.",
        "de": "Reinigung, Einkaufen, Bügeln, gelegentliche Kinderbetreuung und mehr.",
        "ro": "Curățenie, cumpărături, călcat, babysitting ocazional și altele.",
        "uk": "Прибирання, покупки, прасування, періодичний догляд за дітьми та інше.",
        "fil": "Paglilinis, pamimili, pamamalantsa, paminsan-minsang babysitting at iba pa.",
    },
    "home.category.pet_sitter_description": {
        "it": "Assistenza per cani, gatti e altri animali domestici.",
        "en": "Care for dogs, cats and other pets.",
        "fr": "Garde de chiens, chats et autres animaux domestiques.",
        "es": "Cuidado de perros, gatos y otras mascotas.",
        "de": "Betreuung für Hunde, Katzen und andere Haustiere.",
        "ro": "Îngrijire pentru câini, pisici și alte animale de companie.",
        "uk": "Догляд за собаками, котами та іншими домашніми тваринами.",
        "fil": "Pag-aalaga ng aso, pusa at iba pang alagang hayop.",
    },
    "home.category.caregiver_description": {
        "it": "Supporto e compagnia per anziani o persone fragili.",
        "en": "Support and companionship for older or vulnerable people.",
        "fr": "Soutien et compagnie pour les personnes âgées ou fragiles.",
        "es": "Apoyo y compañía para personas mayores o vulnerables.",
        "de": "Unterstützung und Gesellschaft für ältere oder hilfsbedürftige Menschen.",
        "ro": "Sprijin și companie pentru persoane în vârstă sau vulnerabile.",
        "uk": "Підтримка й товариство для літніх або вразливих людей.",
        "fil": "Suporta at kasama para sa matatanda o mahihinang tao.",
    },
    "home.category.tutoring_description": {
        "it": "Lezioni private e sostegno scolastico in varie materie.",
        "en": "Private lessons and study support in different subjects.",
        "fr": "Cours particuliers et soutien scolaire dans différentes matières.",
        "es": "Clases particulares y apoyo escolar en distintas materias.",
        "de": "Privatunterricht und Lernhilfe in verschiedenen Fächern.",
        "ro": "Lecții private și sprijin școlar la diferite materii.",
        "uk": "Приватні уроки та допомога з навчання з різних предметів.",
        "fil": "Pribadong aralin at tulong sa pag-aaral sa iba’t ibang asignatura.",
    },
    "home.category.family_description": {
        "it": "Spazi, attività, feste e laboratori pensati per bambini e famiglie.",
        "en": "Spaces, activities, parties and workshops for children and families.",
        "fr": "Espaces, activités, fêtes et ateliers pour enfants et familles.",
        "es": "Espacios, actividades, fiestas y talleres para niños y familias.",
        "de": "Räume, Aktivitäten, Feste und Workshops für Kinder und Familien.",
        "ro": "Spații, activități, petreceri și ateliere pentru copii și familii.",
        "uk": "Простори, заняття, свята й майстер-класи для дітей та сімей.",
        "fil": "Mga lugar, aktibidad, party at workshop para sa mga bata at pamilya.",
    },
    "home.category.wellbeing_description": {
        "it": "Servizi e trattamenti orientati al benessere e alla cura.",
        "en": "Services and treatments focused on wellbeing and personal care.",
        "fr": "Services et soins axés sur le bien-être et la personne.",
        "es": "Servicios y tratamientos orientados al bienestar y al cuidado personal.",
        "de": "Angebote und Behandlungen für Wohlbefinden und persönliche Pflege.",
        "ro": "Servicii și tratamente pentru bunăstare și îngrijire personală.",
        "uk": "Послуги й процедури для добробуту та догляду за собою.",
        "fil": "Mga serbisyo at paggamot para sa wellbeing at personal na pangangalaga.",
    },
    "home.category.sport_description": {
        "it": "Compagni per allenamenti, passeggiate o attività outdoor.",
        "en": "Companions for training, walks or outdoor activities.",
        "fr": "Partenaires pour entraînements, promenades ou activités en plein air.",
        "es": "Compañeros para entrenar, pasear o hacer actividades al aire libre.",
        "de": "Begleitung für Training, Spaziergänge oder Outdoor-Aktivitäten.",
        "ro": "Parteneri pentru antrenamente, plimbări sau activități în aer liber.",
        "uk": "Компанія для тренувань, прогулянок або активностей на свіжому повітрі.",
        "fil": "Kasama sa ehersisyo, paglalakad o mga outdoor activity.",
    },
    "home.category.events_description": {
        "it": "Eventi locali, incontri, gruppi hobby e occasioni per socializzare.",
        "en": "Local events, meetups, hobby groups and opportunities to socialise.",
        "fr": "Événements locaux, rencontres, groupes de loisirs et occasions de créer du lien.",
        "es": "Eventos locales, encuentros, grupos de aficiones y ocasiones para socializar.",
        "de": "Lokale Veranstaltungen, Treffen, Hobbygruppen und Gelegenheiten zum Kennenlernen.",
        "ro": "Evenimente locale, întâlniri, grupuri de hobby și ocazii de socializare.",
        "uk": "Місцеві події, зустрічі, гуртки за інтересами та можливості для спілкування.",
        "fil": "Mga lokal na event, meetup, hobby group at pagkakataong makipagkilala.",
    },
    "home.category.spaces_description": {
        "it": "Sale, studi, coworking e location da affittare per attività o eventi.",
        "en": "Rooms, studios, coworking spaces and venues to rent for activities or events.",
        "fr": "Salles, studios, coworking et lieux à louer pour des activités ou événements.",
        "es": "Salas, estudios, coworking y espacios en alquiler para actividades o eventos.",
        "de": "Räume, Studios, Coworking-Spaces und Veranstaltungsorte zur Miete.",
        "ro": "Săli, studiouri, spații de coworking și locații de închiriat pentru activități sau evenimente.",
        "uk": "Зали, студії, коворкінги й локації в оренду для занять або подій.",
        "fil": "Mga silid, studio, coworking space at venue na maaaring rentahan para sa aktibidad o event.",
    },
    "home.category.tickets_description": {
        "it": "Scambio o acquisto di biglietti per concerti ed eventi.",
        "en": "Exchange or buy tickets for concerts and events.",
        "fr": "Échange ou achat de billets pour concerts et événements.",
        "es": "Intercambio o compra de entradas para conciertos y eventos.",
        "de": "Tickets für Konzerte und Veranstaltungen tauschen oder kaufen.",
        "ro": "Schimb sau cumpărare de bilete pentru concerte și evenimente.",
        "uk": "Обмін або купівля квитків на концерти й події.",
        "fil": "Magpalitan o bumili ng ticket para sa concert at event.",
    },
    "home.category.coffee_description": {
        "it": "Incontra persone per praticare le lingue e scambiare idee davanti a un caffè.",
        "en": "Meet people to practise languages and share ideas over coffee.",
        "fr": "Rencontrez des personnes pour pratiquer les langues et échanger autour d’un café.",
        "es": "Conoce gente para practicar idiomas e intercambiar ideas tomando un café.",
        "de": "Triff Menschen, um Sprachen zu üben und dich bei einem Kaffee auszutauschen.",
        "ro": "Întâlnește persoane pentru a exersa limbi și a schimba idei la o cafea.",
        "uk": "Знайомтеся з людьми, щоб практикувати мови й обмінюватися думками за кавою.",
        "fil": "Makipagkilala para magsanay ng wika at magbahagi ng ideya habang nagkakape.",
    },
    "home.category.books_description": {
        "it": "Libri scolastici usati e materiale didattico.",
        "en": "Used school books and learning materials.",
        "fr": "Manuels scolaires d’occasion et matériel pédagogique.",
        "es": "Libros escolares usados y material didáctico.",
        "de": "Gebrauchte Schulbücher und Lernmaterialien.",
        "ro": "Manuale școlare second-hand și materiale didactice.",
        "uk": "Уживані шкільні підручники й навчальні матеріали.",
        "fil": "Mga second-hand na aklat pampaaralan at learning material.",
    },
    "dashboard.empty_listings_body": {
        "it": "Crea il tuo primo annuncio per iniziare a ricevere contatti.",
        "en": "Create your first listing to start receiving enquiries.",
        "fr": "Créez votre première annonce pour commencer à recevoir des contacts.",
        "es": "Crea tu primer anuncio para empezar a recibir contactos.",
        "de": "Erstelle deine erste Anzeige, um Anfragen zu erhalten.",
        "ro": "Creează primul anunț pentru a începe să primești contacte.",
        "uk": "Створіть перше оголошення, щоб почати отримувати звернення.",
        "fil": "Gumawa ng unang listing para magsimulang makatanggap ng contact.",
    },
    "dashboard.public_empty_listings_body": {
        "it": "Questo profilo non ha ancora annunci visibili.",
        "en": "This profile does not have any visible listings yet.",
        "fr": "Ce profil n’a pas encore d’annonce visible.",
        "es": "Este perfil aún no tiene anuncios visibles.",
        "de": "Dieses Profil hat noch keine sichtbaren Anzeigen.",
        "ro": "Acest profil nu are încă anunțuri vizibile.",
        "uk": "У цьому профілі ще немає видимих оголошень.",
        "fil": "Wala pang nakikitang listing sa profile na ito.",
    },
    "dashboard.intro_hint": {
        "it": "Per saperne di più vai su Info.",
        "en": "Open Info to learn more.",
        "fr": "Ouvrez Infos pour en savoir plus.",
        "es": "Abre Información para saber más.",
        "de": "Unter Info erfährst du mehr.",
        "ro": "Deschide Informații pentru a afla mai multe.",
        "uk": "Відкрийте розділ «Інформація», щоб дізнатися більше.",
        "fil": "Buksan ang Info para sa iba pang detalye.",
    },
    "settings.back": {
        "it": "Torna alle Impostazioni", "en": "Back to Settings", "fr": "Retour aux paramètres",
        "es": "Volver a Ajustes", "de": "Zurück zu den Einstellungen", "ro": "Înapoi la Setări",
        "uk": "Назад до налаштувань", "fil": "Bumalik sa Settings",
    },
    "settings.change_profile_photo": {
        "it": "Cambia Foto Profilo", "en": "Change profile photo", "fr": "Modifier la photo de profil",
        "es": "Cambiar foto de perfil", "de": "Profilfoto ändern", "ro": "Schimbă fotografia de profil",
        "uk": "Змінити фото профілю", "fil": "Palitan ang profile photo",
    },
    "interests.owner_open_hint": {
        "it": "Apri per vedere e contattare le persone interessate",
        "en": "Open to view and contact interested people",
        "fr": "Ouvrez pour voir et contacter les personnes intéressées",
        "es": "Abre para ver y contactar a las personas interesadas",
        "de": "Öffnen, um interessierte Personen anzusehen und zu kontaktieren",
        "ro": "Deschide pentru a vedea și contacta persoanele interesate",
        "uk": "Відкрийте, щоб переглянути зацікавлених людей і зв’язатися з ними",
        "fil": "Buksan para makita at makontak ang mga interesadong tao",
    },
    "interests.owner_empty_hint": {
        "it": "Qui compariranno le persone interessate al tuo annuncio",
        "en": "People interested in your listing will appear here",
        "fr": "Les personnes intéressées par votre annonce apparaîtront ici",
        "es": "Aquí aparecerán las personas interesadas en tu anuncio",
        "de": "Hier erscheinen Personen, die an deiner Anzeige interessiert sind",
        "ro": "Aici vor apărea persoanele interesate de anunțul tău",
        "uk": "Тут з’являться люди, зацікавлені у вашому оголошенні",
        "fil": "Dito lalabas ang mga taong interesado sa listing mo",
    },
    "reviews.private_intro": {
        "it": "Qui troverai le recensioni ricevute e quelle che hai lasciato ad altri utenti.",
        "en": "Here you will find reviews you received and reviews you left for other users.",
        "fr": "Vous trouverez ici les avis reçus et ceux que vous avez laissés à d’autres utilisateurs.",
        "es": "Aquí encontrarás las reseñas recibidas y las que dejaste a otros usuarios.",
        "de": "Hier findest du erhaltene Bewertungen und Bewertungen, die du anderen gegeben hast.",
        "ro": "Aici vei găsi recenziile primite și cele lăsate altor utilizatori.",
        "uk": "Тут ви знайдете отримані відгуки та відгуки, які залишили іншим користувачам.",
        "fil": "Dito makikita ang mga review na natanggap mo at ibinigay mo sa ibang user.",
    },
    "reviews.private_summary": {
        "it": "Recensioni ricevute: {received}. Recensioni scritte: {written}.",
        "en": "Reviews received: {received}. Reviews written: {written}.",
        "fr": "Avis reçus : {received}. Avis rédigés : {written}.",
        "es": "Reseñas recibidas: {received}. Reseñas escritas: {written}.",
        "de": "Erhaltene Bewertungen: {received}. Geschriebene Bewertungen: {written}.",
        "ro": "Recenzii primite: {received}. Recenzii scrise: {written}.",
        "uk": "Отримані відгуки: {received}. Написані відгуки: {written}.",
        "fil": "Natanggap na review: {received}. Isinulat na review: {written}.",
    },
    "reviews.manage_body": {
        "it": "Puoi leggere le recensioni ricevute, rispondere agli utenti e controllare lo stato delle recensioni che hai scritto.",
        "en": "Read reviews you received, reply to users and check the status of reviews you wrote.",
        "fr": "Consultez les avis reçus, répondez aux utilisateurs et vérifiez le statut des avis rédigés.",
        "es": "Lee las reseñas recibidas, responde a los usuarios y comprueba el estado de las que escribiste.",
        "de": "Lies erhaltene Bewertungen, antworte Nutzern und prüfe den Status deiner Bewertungen.",
        "ro": "Citește recenziile primite, răspunde utilizatorilor și verifică starea recenziilor scrise.",
        "uk": "Читайте отримані відгуки, відповідайте користувачам і перевіряйте стан написаних відгуків.",
        "fil": "Basahin ang natanggap na review, sumagot sa mga user at tingnan ang status ng mga isinulat mong review.",
    },
    "reviews.empty_body": {
        "it": "Quando riceverai o scriverai recensioni, le troverai organizzate in questa sezione.",
        "en": "Reviews you receive or write will be organised in this section.",
        "fr": "Les avis reçus ou rédigés seront organisés dans cette section.",
        "es": "Las reseñas que recibas o escribas aparecerán organizadas en esta sección.",
        "de": "Erhaltene oder geschriebene Bewertungen werden in diesem Bereich angezeigt.",
        "ro": "Recenziile primite sau scrise vor fi organizate în această secțiune.",
        "uk": "Отримані або написані відгуки будуть упорядковані в цьому розділі.",
        "fil": "Ang mga review na matatanggap o isusulat mo ay aayusin sa seksyong ito.",
    },
    "reviews.public_none": {
        "it": "Questo profilo non ha ancora ricevuto recensioni.",
        "en": "This profile has not received any reviews yet.",
        "fr": "Ce profil n’a pas encore reçu d’avis.",
        "es": "Este perfil todavía no ha recibido reseñas.",
        "de": "Dieses Profil hat noch keine Bewertungen erhalten.",
        "ro": "Acest profil nu a primit încă recenzii.",
        "uk": "Цей профіль ще не отримав відгуків.",
        "fil": "Wala pang natatanggap na review ang profile na ito.",
    },
    "reviews.public_empty_body": {
        "it": "Quando questo utente riceverà recensioni approvate, verranno mostrate qui.",
        "en": "Approved reviews received by this user will appear here.",
        "fr": "Les avis approuvés reçus par cet utilisateur apparaîtront ici.",
        "es": "Las reseñas aprobadas que reciba este usuario aparecerán aquí.",
        "de": "Freigegebene Bewertungen für diesen Nutzer werden hier angezeigt.",
        "ro": "Recenziile aprobate primite de acest utilizator vor apărea aici.",
        "uk": "Схвалені відгуки, отримані цим користувачем, з’являться тут.",
        "fil": "Dito lalabas ang mga aprubadong review na matatanggap ng user na ito.",
    },
    "profile.empty_experience": {
        "it": "L’utente non ha ancora inserito esperienze o formazione.",
        "en": "This user has not added any experience or education yet.",
        "fr": "Cet utilisateur n’a pas encore ajouté d’expérience ni de formation.",
        "es": "Este usuario aún no ha añadido experiencia ni formación.",
        "de": "Dieser Nutzer hat noch keine Erfahrung oder Ausbildung hinzugefügt.",
        "ro": "Acest utilizator nu a adăugat încă experiență sau studii.",
        "uk": "Цей користувач ще не додав досвід або освіту.",
        "fil": "Wala pang idinagdag na experience o education ang user na ito.",
    },
    "profile.empty_experience_full": {
        "it": "L’utente non ha ancora inserito esperienze, formazione o certificazioni.",
        "en": "This user has not added any experience, education or certifications yet.",
        "fr": "Cet utilisateur n’a pas encore ajouté d’expérience, de formation ni de certification.",
        "es": "Este usuario aún no ha añadido experiencia, formación ni certificaciones.",
        "de": "Dieser Nutzer hat noch keine Erfahrung, Ausbildung oder Zertifikate hinzugefügt.",
        "ro": "Acest utilizator nu a adăugat încă experiență, studii sau certificări.",
        "uk": "Цей користувач ще не додав досвід, освіту або сертифікати.",
        "fil": "Wala pang idinagdag na experience, education o certification ang user na ito.",
    },
    "profile.empty_description": {
        "it": "L’utente non ha ancora aggiunto una descrizione personale.",
        "en": "This user has not added a personal description yet.",
        "fr": "Cet utilisateur n’a pas encore ajouté de description personnelle.",
        "es": "Este usuario aún no ha añadido una descripción personal.",
        "de": "Dieser Nutzer hat noch keine persönliche Beschreibung hinzugefügt.",
        "ro": "Acest utilizator nu a adăugat încă o descriere personală.",
        "uk": "Цей користувач ще не додав особистий опис.",
        "fil": "Wala pang idinagdag na personal na description ang user na ito.",
    },
    "profile.description_placeholder": {
        "it": "Es. Mi piace aiutare le persone con serietà, empatia e attenzione. Ho maturato esperienza sul campo e cerco sempre di offrire un servizio affidabile e umano.",
        "en": "E.g. I enjoy helping people with care, empathy and attention. I have hands-on experience and always aim to offer a reliable, human service.",
        "fr": "Ex. J’aime aider les personnes avec sérieux, empathie et attention. Mon expérience de terrain me permet d’offrir un service fiable et humain.",
        "es": "Ej. Me gusta ayudar a las personas con seriedad, empatía y atención. Tengo experiencia práctica y procuro ofrecer un servicio fiable y humano.",
        "de": "Z. B. Ich helfe Menschen gern zuverlässig, einfühlsam und aufmerksam. Ich habe praktische Erfahrung und biete einen menschlichen Service.",
        "ro": "Ex. Îmi place să ajut oamenii cu seriozitate, empatie și atenție. Am experiență practică și ofer un serviciu de încredere și uman.",
        "uk": "Напр. Мені подобається допомагати людям відповідально, з емпатією та увагою. Я маю практичний досвід і прагну надавати надійну й людяну допомогу.",
        "fil": "Hal. Gusto kong tumulong nang maingat, may malasakit at responsable. May praktikal akong karanasan at sinisikap kong magbigay ng maaasahan at makataong serbisyo.",
    },
    "content.write_italian_profile_note": {
        "it": "Scrivi questo testo in italiano, perché sarà mostrato pubblicamente senza traduzione automatica.",
        "en": "Write this text in Italian because it will be shown publicly without automatic translation.",
        "fr": "Écrivez ce texte en italien : il sera affiché publiquement sans traduction automatique.",
        "es": "Escribe este texto en italiano: se mostrará públicamente sin traducción automática.",
        "de": "Schreibe diesen Text auf Italienisch. Er wird öffentlich ohne automatische Übersetzung angezeigt.",
        "ro": "Scrie acest text în italiană: va fi afișat public fără traducere automată.",
        "uk": "Напишіть цей текст італійською мовою: він буде опублікований без автоматичного перекладу.",
        "fil": "Isulat ang tekstong ito sa Italian dahil ipapakita ito sa publiko nang walang awtomatikong pagsasalin.",
    },
    "content.write_italian_listing_note": {
        "it": "Scrivi la descrizione in italiano. Se ti serve aiuto, usa Aiuto scrittura per tradurla e migliorarla.",
        "en": "Write the description in Italian. If you need help, use Writing help to translate and improve it.",
        "fr": "Rédigez la description en italien. Si nécessaire, utilisez Aide à la rédaction pour la traduire et l’améliorer.",
        "es": "Escribe la descripción en italiano. Si necesitas ayuda, usa Ayuda de escritura para traducirla y mejorarla.",
        "de": "Schreibe die Beschreibung auf Italienisch. Nutze bei Bedarf die Schreibhilfe zum Übersetzen und Verbessern.",
        "ro": "Scrie descrierea în italiană. Dacă ai nevoie de ajutor, folosește Asistență la scriere pentru traducere și îmbunătățire.",
        "uk": "Напишіть опис італійською мовою. За потреби скористайтеся допомогою з написання, щоб перекласти й покращити текст.",
        "fil": "Isulat ang paglalarawan sa Italian. Kung kailangan mo ng tulong, gamitin ang Writing help para isalin at pagandahin ito.",
    },
    # Schede strutturate di esperienza, formazione e certificazioni.
    # Le chiavi sono usate anche dal JavaScript del popup: in questo modo i
    # testi creati dopo il caricamento non dipendono dal traduttore del DOM.
    "profile_card.close_sheet": {
        "it": "Chiudi la scheda", "en": "Close profile card", "fr": "Fermer la fiche",
        "es": "Cerrar la ficha", "de": "Profilkarte schließen", "ro": "Închide fișa",
        "uk": "Закрити картку", "fil": "Isara ang profile card",
    },
    "profile_card.sheet": {
        "it": "Scheda del profilo", "en": "Profile card", "fr": "Fiche du profil",
        "es": "Ficha del perfil", "de": "Profilkarte", "ro": "Fișă de profil",
        "uk": "Картка профілю", "fil": "Profile card",
    },
    "profile_card.details": {
        "it": "Dettagli", "en": "Details", "fr": "Détails", "es": "Detalles",
        "de": "Details", "ro": "Detalii", "uk": "Деталі", "fil": "Mga detalye",
    },
    "profile_card.declared_information": {
        "it": "Informazioni dichiarate dall’utente.",
        "en": "Information provided by the user.",
        "fr": "Informations déclarées par l’utilisateur.",
        "es": "Información declarada por el usuario.",
        "de": "Vom Nutzer angegebene Informationen.",
        "ro": "Informații declarate de utilizator.",
        "uk": "Інформація, надана користувачем.",
        "fil": "Impormasyong ibinigay ng user.",
    },
    "profile_card.catalog_title": {
        "it": "Titolo dal catalogo", "en": "Title from the catalogue",
        "fr": "Intitulé du catalogue", "es": "Título del catálogo",
        "de": "Titel aus dem Katalog", "ro": "Titlu din catalog",
        "uk": "Назва з каталогу", "fil": "Pamagat mula sa catalog",
    },
    "profile_card.custom_title": {
        "it": "Titolo personalizzato", "en": "Custom title", "fr": "Intitulé personnalisé",
        "es": "Título personalizado", "de": "Eigener Titel", "ro": "Titlu personalizat",
        "uk": "Власна назва", "fil": "Custom na pamagat",
    },
    "profile_card.catalog_help": {
        "it": "Scegli una voce oppure scrivi un titolo personalizzato.",
        "en": "Choose an item or enter a custom title.",
        "fr": "Choisissez une entrée ou saisissez un intitulé personnalisé.",
        "es": "Elige una opción o escribe un título personalizado.",
        "de": "Wähle einen Eintrag oder gib einen eigenen Titel ein.",
        "ro": "Alege o opțiune sau scrie un titlu personalizat.",
        "uk": "Виберіть варіант або введіть власну назву.",
        "fil": "Pumili ng item o maglagay ng custom na pamagat.",
    },
    "profile_card.card_title": {
        "it": "Titolo della scheda", "en": "Card title", "fr": "Intitulé de la fiche",
        "es": "Título de la ficha", "de": "Titel der Profilkarte", "ro": "Titlul fișei",
        "uk": "Назва картки", "fil": "Pamagat ng card",
    },
    "profile_card.scope": {
        "it": "Ambito", "en": "Field", "fr": "Domaine", "es": "Ámbito",
        "de": "Bereich", "ro": "Domeniu", "uk": "Сфера", "fil": "Larangan",
    },
    "profile_card.no_scope": {
        "it": "Nessun ambito specifico", "en": "No specific field",
        "fr": "Aucun domaine spécifique", "es": "Ningún ámbito específico",
        "de": "Kein bestimmter Bereich", "ro": "Niciun domeniu specific",
        "uk": "Без конкретної сфери", "fil": "Walang partikular na larangan",
    },
    "profile_card.issuer": {
        "it": "Ente o organizzazione", "en": "Issuing body or organisation",
        "fr": "Organisme ou organisation", "es": "Entidad u organización",
        "de": "Ausstellende Stelle oder Organisation", "ro": "Instituție sau organizație",
        "uk": "Установа або організація", "fil": "Institusyon o organisasyon",
    },
    "profile_card.place": {
        "it": "Luogo", "en": "Location", "fr": "Lieu", "es": "Lugar",
        "de": "Ort", "ro": "Loc", "uk": "Місце", "fil": "Lugar",
    },
    "profile_card.code": {
        "it": "Codice o numero", "en": "Code or number", "fr": "Code ou numéro",
        "es": "Código o número", "de": "Code oder Nummer", "ro": "Cod sau număr",
        "uk": "Код або номер", "fil": "Code o numero",
    },
    "profile_card.optional": {
        "it": "facoltativo", "en": "optional", "fr": "facultatif", "es": "opcional",
        "de": "optional", "ro": "opțional", "uk": "необов’язково", "fil": "opsyonal",
    },
    "profile_card.optional_plural": {
        "it": "facoltativi", "en": "optional", "fr": "facultatifs", "es": "opcionales",
        "de": "optional", "ro": "opționale", "uk": "необов’язково", "fil": "opsyonal",
    },
    "profile_card.start_date": {
        "it": "Data di inizio", "en": "Start date", "fr": "Date de début",
        "es": "Fecha de inicio", "de": "Startdatum", "ro": "Data de început",
        "uk": "Дата початку", "fil": "Petsa ng simula",
    },
    "profile_card.end_date": {
        "it": "Data di fine", "en": "End date", "fr": "Date de fin",
        "es": "Fecha de finalización", "de": "Enddatum", "ro": "Data de încheiere",
        "uk": "Дата завершення", "fil": "Petsa ng pagtatapos",
    },
    "profile_card.ongoing_description": {
        "it": "Esperienza o percorso ancora in corso", "en": "Experience or course still in progress",
        "fr": "Expérience ou parcours toujours en cours", "es": "Experiencia o formación todavía en curso",
        "de": "Erfahrung oder Ausbildung läuft noch", "ro": "Experiență sau parcurs încă în desfășurare",
        "uk": "Досвід або навчання ще триває", "fil": "Patuloy pa ang karanasan o kurso",
    },
    "profile_card.issue_date": {
        "it": "Data di rilascio", "en": "Issue date", "fr": "Date de délivrance",
        "es": "Fecha de expedición", "de": "Ausstellungsdatum", "ro": "Data emiterii",
        "uk": "Дата видачі", "fil": "Petsa ng pag-isyu",
    },
    "profile_card.expiry_date": {
        "it": "Data di scadenza", "en": "Expiry date", "fr": "Date d’expiration",
        "es": "Fecha de caducidad", "de": "Ablaufdatum", "ro": "Data expirării",
        "uk": "Дата закінчення дії", "fil": "Petsa ng pag-expire",
    },
    "profile_card.request_check": {
        "it": "Richiedi il controllo di MyLocalCare", "en": "Request a MyLocalCare check",
        "fr": "Demander un contrôle MyLocalCare", "es": "Solicitar una comprobación de MyLocalCare",
        "de": "Prüfung durch MyLocalCare anfordern", "ro": "Solicită verificarea MyLocalCare",
        "uk": "Запросити перевірку MyLocalCare", "fil": "Humiling ng pagsusuri ng MyLocalCare",
    },
    "profile_card.request_benefit": {
        "it": "Se il controllo ha esito positivo, nel profilo pubblico comparirà un badge che indica cosa MyLocalCare ha realmente visionato o riscontrato. Anche senza controllo, la scheda resta visibile come «Dichiarato dall’utente».",
        "en": "If the check is successful, your public profile will show a badge stating what MyLocalCare actually viewed or confirmed. Even without a check, the card remains visible as ‘Declared by the user’.",
        "fr": "Si le contrôle est positif, votre profil public affichera un badge indiquant ce que MyLocalCare a réellement consulté ou vérifié. Même sans contrôle, la fiche reste visible comme « Déclaré par l’utilisateur ».",
        "es": "Si la comprobación es positiva, tu perfil público mostrará una insignia que indica lo que MyLocalCare ha revisado o contrastado realmente. Incluso sin comprobación, la ficha sigue visible como «Declarado por el usuario».",
        "de": "Bei erfolgreicher Prüfung zeigt dein öffentliches Profil ein Abzeichen mit dem Hinweis, was MyLocalCare tatsächlich eingesehen oder überprüft hat. Auch ohne Prüfung bleibt die Profilkarte als „Vom Nutzer angegeben“ sichtbar.",
        "ro": "Dacă verificarea are un rezultat pozitiv, profilul public va afișa o insignă care arată ce a consultat sau confirmat efectiv MyLocalCare. Chiar și fără verificare, fișa rămâne vizibilă ca „Declarat de utilizator”.",
        "uk": "Якщо перевірка успішна, у відкритому профілі з’явиться позначка з уточненням, що саме MyLocalCare переглянув або підтвердив. Навіть без перевірки картка залишається видимою як «Заявлено користувачем».",
        "fil": "Kapag matagumpay ang pagsusuri, may badge sa public profile na nagsasabi kung ano ang aktuwal na tiningnan o kinumpirma ng MyLocalCare. Kahit walang pagsusuri, makikita pa rin ang card bilang ‘Idineklara ng user’.",
    },
    "profile_card.request_process": {
        "it": "Dopo la richiesta, MyLocalCare ti contatterà in chat o via email per concordare il controllo. Non inviare documenti o fotografie: se necessario, ti indicheremo come mostrare l’originale senza conservarne copia.",
        "en": "After your request, MyLocalCare will contact you by chat or email to arrange the check. Do not send documents or photographs: if needed, we will explain how to show the original without keeping a copy.",
        "fr": "Après votre demande, MyLocalCare vous contactera par chat ou par e-mail pour organiser le contrôle. N’envoyez ni documents ni photographies : si nécessaire, nous vous indiquerons comment montrer l’original sans en conserver de copie.",
        "es": "Después de la solicitud, MyLocalCare te contactará por chat o correo electrónico para acordar la comprobación. No envíes documentos ni fotografías: si es necesario, te indicaremos cómo mostrar el original sin conservar una copia.",
        "de": "Nach deiner Anfrage kontaktiert dich MyLocalCare per Chat oder E-Mail, um die Prüfung zu vereinbaren. Sende keine Dokumente oder Fotos: Falls nötig, erklären wir dir, wie du das Original zeigen kannst, ohne dass eine Kopie gespeichert wird.",
        "ro": "După solicitare, MyLocalCare te va contacta prin chat sau e-mail pentru a stabili verificarea. Nu trimite documente sau fotografii: dacă este necesar, îți vom explica cum să arăți originalul fără să păstrăm o copie.",
        "uk": "Після запиту MyLocalCare зв’яжеться з вами в чаті або електронною поштою, щоб узгодити перевірку. Не надсилайте документи чи фотографії: за потреби ми пояснимо, як показати оригінал без збереження копії.",
        "fil": "Pagkatapos ng request, kokontakin ka ng MyLocalCare sa chat o email para ayusin ang pagsusuri. Huwag magpadala ng dokumento o litrato: kung kailangan, ipapaliwanag namin kung paano ipakita ang orihinal nang walang itinatagong kopya.",
    },
    "profile_card.request_help": {
        "it": "MyLocalCare potrà visionare un documento senza conservarne copia, consultare una fonte pubblica o contattare l’ente indicato. Il controllo riguarda solo i dati della scheda e non certifica idoneità professionale, autenticità assoluta o abilitazione al lavoro.",
        "en": "MyLocalCare may view a document without keeping a copy, consult a public source or contact the named organisation. The check only covers the card details and does not certify professional suitability, absolute authenticity or eligibility to work.",
        "fr": "MyLocalCare pourra consulter un document sans en conserver de copie, vérifier une source publique ou contacter l’organisme indiqué. Le contrôle porte uniquement sur les données de la fiche et ne certifie ni l’aptitude professionnelle, ni l’authenticité absolue, ni le droit au travail.",
        "es": "MyLocalCare podrá revisar un documento sin guardar una copia, consultar una fuente pública o contactar con la entidad indicada. La comprobación solo se refiere a los datos de la ficha y no certifica la idoneidad profesional, la autenticidad absoluta ni la autorización para trabajar.",
        "de": "MyLocalCare kann ein Dokument einsehen, ohne eine Kopie aufzubewahren, eine öffentliche Quelle prüfen oder die angegebene Stelle kontaktieren. Die Prüfung betrifft nur die Angaben der Profilkarte und bestätigt weder berufliche Eignung noch absolute Echtheit oder Arbeitsberechtigung.",
        "ro": "MyLocalCare poate consulta un document fără a păstra o copie, poate verifica o sursă publică sau poate contacta instituția indicată. Verificarea privește doar datele fișei și nu certifică aptitudinea profesională, autenticitatea absolută sau dreptul de muncă.",
        "uk": "MyLocalCare може переглянути документ без збереження копії, перевірити відкрите джерело або зв’язатися із зазначеною установою. Перевірка стосується лише даних картки й не підтверджує професійну придатність, абсолютну справжність чи право на роботу.",
        "fil": "Maaaring tingnan ng MyLocalCare ang isang dokumento nang hindi nagtatago ng kopya, kumonsulta sa pampublikong source, o kontakin ang nakasaad na institusyon. Ang pagsusuri ay para lamang sa detalye ng card at hindi nagpapatunay ng professional suitability, ganap na authenticity, o karapatang magtrabaho.",
    },
    "profile_card.public_data_notice": {
        "it": "Se il profilo è pubblico, i dati della scheda saranno visibili ai visitatori, escluso il codice della qualifica. Non inserire dati sanitari, documenti d’identità o dati personali di terzi.",
        "en": "If your profile is public, the card details will be visible to visitors, except for the qualification code. Do not enter health data, identity documents or another person’s personal data.",
        "fr": "Si votre profil est public, les données de la fiche seront visibles par les visiteurs, à l’exception du code de qualification. N’insérez pas de données de santé, de documents d’identité ni de données personnelles de tiers.",
        "es": "Si tu perfil es público, los datos de la ficha serán visibles para los visitantes, excepto el código de la cualificación. No introduzcas datos de salud, documentos de identidad ni datos personales de terceros.",
        "de": "Wenn dein Profil öffentlich ist, sind die Angaben der Profilkarte für Besucher sichtbar; ausgenommen ist der Qualifikationscode. Gib keine Gesundheitsdaten, Ausweisdokumente oder personenbezogenen Daten Dritter ein.",
        "ro": "Dacă profilul este public, datele fișei vor fi vizibile vizitatorilor, cu excepția codului calificării. Nu introduce date medicale, documente de identitate sau date personale ale altor persoane.",
        "uk": "Якщо профіль відкритий, дані картки будуть видимі відвідувачам, крім коду кваліфікації. Не вводьте медичні дані, документи, що посвідчують особу, або персональні дані третіх осіб.",
        "fil": "Kung public ang profile, makikita ng mga bisita ang detalye ng card maliban sa qualification code. Huwag maglagay ng health data, identity document, o personal data ng ibang tao.",
    },
    "profile_card.public_preview": {
        "it": "Nel profilo pubblico:", "en": "On the public profile:",
        "fr": "Sur le profil public :", "es": "En el perfil público:",
        "de": "Im öffentlichen Profil:", "ro": "În profilul public:",
        "uk": "У відкритому профілі:", "fil": "Sa public profile:",
    },
    "profile_card.linked_card": {
        "it": "Scheda collegata a questo campo", "en": "Card linked to this field",
        "fr": "Fiche liée à ce champ", "es": "Ficha vinculada a este campo",
        "de": "Mit diesem Feld verknüpfte Profilkarte", "ro": "Fișă asociată acestui câmp",
        "uk": "Картка, пов’язана з цим полем", "fil": "Card na naka-link sa field na ito",
    },
    "profile_card.view_details": {
        "it": "Vedi dettagli", "en": "View details", "fr": "Voir les détails",
        "es": "Ver detalles", "de": "Details ansehen", "ro": "Vezi detaliile",
        "uk": "Переглянути деталі", "fil": "Tingnan ang detalye",
    },
    "profile_card.no_contacts_note": {
        "it": "Non inserire telefono, email, WhatsApp, link o altri recapiti nelle schede. Usa la sezione Contatti.",
        "en": "Do not include phone numbers, email, WhatsApp, links or other contact details in profile cards. Use the Contacts section.",
        "fr": "N’indiquez pas de téléphone, d’e-mail, de WhatsApp, de liens ni d’autres coordonnées dans les fiches. Utilisez la section Contacts.",
        "es": "No incluyas teléfono, correo electrónico, WhatsApp, enlaces ni otros datos de contacto en las fichas. Usa la sección Contactos.",
        "de": "Gib in Profilkarten keine Telefonnummern, E-Mail-Adressen, WhatsApp-Daten, Links oder andere Kontaktdaten an. Nutze den Bereich Kontakte.",
        "ro": "Nu introduce numere de telefon, e-mail, WhatsApp, linkuri sau alte date de contact în fișe. Folosește secțiunea Contacte.",
        "uk": "Не додавайте до карток телефон, електронну пошту, WhatsApp, посилання чи інші контактні дані. Використовуйте розділ «Контакти».",
        "fil": "Huwag maglagay ng telepono, email, WhatsApp, link o iba pang contact details sa mga card. Gamitin ang seksyong Contacts.",
    },
    "profile_card.error_contacts": {
        "it": "La scheda non può contenere telefono, email, WhatsApp, link o altri recapiti. Usa la sezione Contatti.",
        "en": "The card cannot contain phone numbers, email, WhatsApp, links or other contact details. Use the Contacts section.",
        "fr": "La fiche ne peut pas contenir de téléphone, d’e-mail, de WhatsApp, de liens ni d’autres coordonnées. Utilisez la section Contacts.",
        "es": "La ficha no puede contener teléfono, correo electrónico, WhatsApp, enlaces ni otros datos de contacto. Usa la sección Contactos.",
        "de": "Die Profilkarte darf keine Telefonnummern, E-Mail-Adressen, WhatsApp-Daten, Links oder andere Kontaktdaten enthalten. Nutze den Bereich Kontakte.",
        "ro": "Fișa nu poate conține numere de telefon, e-mail, WhatsApp, linkuri sau alte date de contact. Folosește secțiunea Contacte.",
        "uk": "Картка не може містити телефон, електронну пошту, WhatsApp, посилання чи інші контактні дані. Використовуйте розділ «Контакти».",
        "fil": "Hindi maaaring maglaman ang card ng telepono, email, WhatsApp, link o iba pang contact details. Gamitin ang seksyong Contacts.",
    },
    "profile_card.delete": {
        "it": "Elimina scheda", "en": "Delete card", "fr": "Supprimer la fiche",
        "es": "Eliminar ficha", "de": "Profilkarte löschen", "ro": "Șterge fișa",
        "uk": "Видалити картку", "fil": "I-delete ang card",
    },
    "profile_card.save": {
        "it": "Salva scheda", "en": "Save card", "fr": "Enregistrer la fiche",
        "es": "Guardar ficha", "de": "Profilkarte speichern", "ro": "Salvează fișa",
        "uk": "Зберегти картку", "fil": "I-save ang card",
    },
    "profile_card.type_experience": {
        "it": "Esperienza", "en": "Experience", "fr": "Expérience", "es": "Experiencia",
        "de": "Erfahrung", "ro": "Experiență", "uk": "Досвід", "fil": "Karanasan",
    },
    "profile_card.type_education": {
        "it": "Formazione", "en": "Education", "fr": "Formation", "es": "Formación",
        "de": "Ausbildung", "ro": "Educație", "uk": "Освіта", "fil": "Edukasyon",
    },
    "profile_card.type_certificate": {
        "it": "Certificazione o attestato", "en": "Certification or certificate",
        "fr": "Certification ou attestation", "es": "Certificación o acreditación",
        "de": "Zertifizierung oder Bescheinigung", "ro": "Certificare sau atestat",
        "uk": "Сертифікація або посвідчення", "fil": "Sertipikasyon o certificate",
    },
    "profile_card.state_declared": {
        "it": "Dichiarato dall’utente", "en": "Declared by the user",
        "fr": "Déclaré par l’utilisateur", "es": "Declarado por el usuario",
        "de": "Vom Nutzer angegeben", "ro": "Declarat de utilizator",
        "uk": "Заявлено користувачем", "fil": "Idineklara ng user",
    },
    "profile_card.state_requested": {
        "it": "Controllo richiesto", "en": "Check requested", "fr": "Contrôle demandé",
        "es": "Comprobación solicitada", "de": "Prüfung angefordert", "ro": "Verificare solicitată",
        "uk": "Перевірку запитано", "fil": "Hiniling ang pagsusuri",
    },
    "profile_card.state_document": {
        "it": "Documento visionato da MyLocalCare", "en": "Document viewed by MyLocalCare",
        "fr": "Document consulté par MyLocalCare", "es": "Documento revisado por MyLocalCare",
        "de": "Dokument von MyLocalCare eingesehen", "ro": "Document consultat de MyLocalCare",
        "uk": "Документ переглянуто MyLocalCare", "fil": "Dokumentong sinuri ng MyLocalCare",
    },
    "profile_card.state_feedback": {
        "it": "Riscontro effettuato da MyLocalCare", "en": "Check completed by MyLocalCare",
        "fr": "Contrôle effectué par MyLocalCare", "es": "Comprobación realizada por MyLocalCare",
        "de": "Prüfung durch MyLocalCare durchgeführt", "ro": "Verificare efectuată de MyLocalCare",
        "uk": "Перевірку проведено MyLocalCare", "fil": "Pagsusuring ginawa ng MyLocalCare",
    },
    "profile_card.state_unconfirmed": {
        "it": "Controllo non confermato", "en": "Check not confirmed",
        "fr": "Contrôle non confirmé", "es": "Comprobación no confirmada",
        "de": "Prüfung nicht bestätigt", "ro": "Verificare neconfirmată",
        "uk": "Перевірку не підтверджено", "fil": "Hindi nakumpirma ang pagsusuri",
    },
    "profile_card.state_unverifiable": {
        "it": "Controllo non verificabile", "en": "Check could not be completed",
        "fr": "Contrôle impossible à effectuer", "es": "No se pudo completar la comprobación",
        "de": "Prüfung nicht durchführbar", "ro": "Verificarea nu a putut fi finalizată",
        "uk": "Перевірку неможливо завершити", "fil": "Hindi makumpleto ang pagsusuri",
    },
    "profile_card.unverifiable_help": {
        "it": "I dati o le prove disponibili non hanno permesso il controllo. Aggiorna la scheda con ente, date, codice o altre informazioni utili: dopo una modifica potrai richiedere un nuovo controllo.",
        "en": "The available details or evidence did not allow the check to be completed. Update the card with the organisation, dates, code or other useful information; after a change, you can request another check.",
        "fr": "Les informations ou justificatifs disponibles n’ont pas permis d’effectuer le contrôle. Mettez à jour la fiche avec l’organisme, les dates, le code ou d’autres informations utiles ; après une modification, vous pourrez demander un nouveau contrôle.",
        "es": "Los datos o pruebas disponibles no permitieron completar la comprobación. Actualiza la ficha con la entidad, las fechas, el código u otra información útil; después de modificarla podrás solicitar otra comprobación.",
        "de": "Die verfügbaren Angaben oder Nachweise reichten für die Prüfung nicht aus. Ergänze die Profilkarte um Stelle, Daten, Code oder andere hilfreiche Angaben; nach einer Änderung kannst du eine neue Prüfung anfordern.",
        "ro": "Datele sau dovezile disponibile nu au permis finalizarea verificării. Actualizează fișa cu instituția, datele, codul sau alte informații utile; după modificare poți solicita o nouă verificare.",
        "uk": "Наявних даних або доказів було недостатньо для перевірки. Оновіть картку, додавши установу, дати, код чи іншу корисну інформацію; після зміни можна буде подати новий запит.",
        "fil": "Hindi sapat ang kasalukuyang detalye o patunay para makumpleto ang pagsusuri. I-update ang card gamit ang institusyon, mga petsa, code, o iba pang kapaki-pakinabang na impormasyon; pagkatapos ng pagbabago, maaari kang humiling muli.",
    },
    "profile_card.state_expired": {
        "it": "Controllo scaduto", "en": "Check expired", "fr": "Contrôle expiré",
        "es": "Comprobación caducada", "de": "Prüfung abgelaufen", "ro": "Verificare expirată",
        "uk": "Термін перевірки минув", "fil": "Nag-expire ang pagsusuri",
    },
    "profile_card.state_revoked": {
        "it": "Controllo revocato", "en": "Check revoked", "fr": "Contrôle révoqué",
        "es": "Comprobación revocada", "de": "Prüfung widerrufen", "ro": "Verificare revocată",
        "uk": "Перевірку відкликано", "fil": "Binawi ang pagsusuri",
    },
    "profile_card.edit": {
        "it": "Modifica scheda", "en": "Edit card", "fr": "Modifier la fiche",
        "es": "Editar ficha", "de": "Profilkarte bearbeiten", "ro": "Modifică fișa",
        "uk": "Редагувати картку", "fil": "I-edit ang card",
    },
    "profile_card.new": {
        "it": "Nuova scheda", "en": "New card", "fr": "Nouvelle fiche",
        "es": "Nueva ficha", "de": "Neue Profilkarte", "ro": "Fișă nouă",
        "uk": "Нова картка", "fil": "Bagong card",
    },
    "profile_card.edit_help": {
        "it": "Aggiorna i dettagli dichiarati nel tuo profilo.",
        "en": "Update the details provided on your profile.",
        "fr": "Mettez à jour les informations déclarées sur votre profil.",
        "es": "Actualiza los datos declarados en tu perfil.",
        "de": "Aktualisiere die Angaben in deinem Profil.",
        "ro": "Actualizează detaliile declarate în profil.",
        "uk": "Оновіть дані, зазначені у вашому профілі.",
        "fil": "I-update ang mga detalyeng inilagay sa iyong profile.",
    },
    "profile_card.new_help": {
        "it": "Aggiungi dettagli ordinati senza modificare il testo già presente.",
        "en": "Add structured details without changing the text already present.",
        "fr": "Ajoutez des informations structurées sans modifier le texte existant.",
        "es": "Añade datos estructurados sin modificar el texto existente.",
        "de": "Füge strukturierte Angaben hinzu, ohne den vorhandenen Text zu ändern.",
        "ro": "Adaugă detalii structurate fără a modifica textul existent.",
        "uk": "Додайте структуровані дані, не змінюючи наявний текст.",
        "fil": "Magdagdag ng maayos na detalye nang hindi binabago ang kasalukuyang teksto.",
    },
    "profile_card.in_progress": {
        "it": "In corso", "en": "In progress", "fr": "En cours", "es": "En curso",
        "de": "Laufend", "ro": "În curs", "uk": "Триває", "fil": "Kasalukuyan",
    },
    "profile_card.note": {
        "it": "Nota MyLocalCare", "en": "MyLocalCare note", "fr": "Note MyLocalCare",
        "es": "Nota de MyLocalCare", "de": "Hinweis von MyLocalCare", "ro": "Notă MyLocalCare",
        "uk": "Примітка MyLocalCare", "fil": "Tala ng MyLocalCare",
    },
    "profile_card.open": {
        "it": "Apri scheda", "en": "Open card", "fr": "Ouvrir la fiche",
        "es": "Abrir ficha", "de": "Profilkarte öffnen", "ro": "Deschide fișa",
        "uk": "Відкрити картку", "fil": "Buksan ang card",
    },
    "profile_card.short": {
        "it": "Scheda", "en": "Card", "fr": "Fiche", "es": "Ficha",
        "de": "Profilkarte", "ro": "Fișă", "uk": "Картка", "fil": "Card",
    },
    "profile_card.add": {
        "it": "Aggiungi scheda", "en": "Add card", "fr": "Ajouter une fiche",
        "es": "Añadir ficha", "de": "Profilkarte hinzufügen", "ro": "Adaugă fișă",
        "uk": "Додати картку", "fil": "Magdagdag ng card",
    },
    "profile_card.saving": {
        "it": "Salvataggio…", "en": "Saving…", "fr": "Enregistrement…",
        "es": "Guardando…", "de": "Wird gespeichert…", "ro": "Se salvează…",
        "uk": "Збереження…", "fil": "Sine-save…",
    },
    "profile_card.deleting": {
        "it": "Eliminazione…", "en": "Deleting…", "fr": "Suppression…",
        "es": "Eliminando…", "de": "Wird gelöscht…", "ro": "Se șterge…",
        "uk": "Видалення…", "fil": "Dine-delete…",
    },
    "profile_card.saved": {
        "it": "Scheda salvata e già visibile nel profilo come dichiarata dall’utente.",
        "en": "Card saved and already visible on the profile as declared by the user.",
        "fr": "Fiche enregistrée et déjà visible sur le profil comme déclarée par l’utilisateur.",
        "es": "Ficha guardada y ya visible en el perfil como declarada por el usuario.",
        "de": "Profilkarte gespeichert und bereits als vom Nutzer angegeben im Profil sichtbar.",
        "ro": "Fișa a fost salvată și este deja vizibilă în profil ca declarată de utilizator.",
        "uk": "Картку збережено; вона вже відображається у профілі як заявлена користувачем.",
        "fil": "Na-save ang card at makikita na sa profile bilang idineklara ng user.",
    },
    "profile_card.saved_requested": {
        "it": "Scheda salvata e controllo richiesto. Nel frattempo è già visibile come dichiarata dall’utente.",
        "en": "Card saved and check requested. In the meantime, it is already visible as declared by the user.",
        "fr": "Fiche enregistrée et contrôle demandé. En attendant, elle est déjà visible comme déclarée par l’utilisateur.",
        "es": "Ficha guardada y comprobación solicitada. Mientras tanto, ya es visible como declarada por el usuario.",
        "de": "Profilkarte gespeichert und Prüfung angefordert. Bis dahin ist sie bereits als vom Nutzer angegeben sichtbar.",
        "ro": "Fișa a fost salvată și verificarea a fost solicitată. Între timp, este deja vizibilă ca declarată de utilizator.",
        "uk": "Картку збережено й перевірку запитано. Тим часом вона вже відображається як заявлена користувачем.",
        "fil": "Na-save ang card at hiniling ang pagsusuri. Habang naghihintay, makikita na ito bilang idineklara ng user.",
    },
    "profile_card.error_save": {
        "it": "Non è stato possibile salvare la scheda.",
        "en": "The card could not be saved.", "fr": "Impossible d’enregistrer la fiche.",
        "es": "No se ha podido guardar la ficha.", "de": "Die Profilkarte konnte nicht gespeichert werden.",
        "ro": "Fișa nu a putut fi salvată.", "uk": "Не вдалося зберегти картку.",
        "fil": "Hindi na-save ang card.",
    },
    "profile_card.error_delete": {
        "it": "Non è stato possibile eliminare la scheda.",
        "en": "The card could not be deleted.", "fr": "Impossible de supprimer la fiche.",
        "es": "No se ha podido eliminar la ficha.", "de": "Die Profilkarte konnte nicht gelöscht werden.",
        "ro": "Fișa nu a putut fi ștearsă.", "uk": "Не вдалося видалити картку.",
        "fil": "Hindi na-delete ang card.",
    },
    "profile_card.error_operation": {
        "it": "Operazione non riuscita.", "en": "Operation failed.",
        "fr": "Échec de l’opération.", "es": "La operación ha fallado.",
        "de": "Vorgang fehlgeschlagen.", "ro": "Operațiunea a eșuat.",
        "uk": "Не вдалося виконати операцію.", "fil": "Hindi nagtagumpay ang operasyon.",
    },
    "profile_card.error_title": {
        "it": "Inserisci il titolo della scheda.", "en": "Enter the card title.",
        "fr": "Saisissez l’intitulé de la fiche.", "es": "Introduce el título de la ficha.",
        "de": "Gib den Titel der Profilkarte ein.", "ro": "Introdu titlul fișei.",
        "uk": "Введіть назву картки.", "fil": "Ilagay ang pamagat ng card.",
    },
    "profile_card.error_issuer": {
        "it": "Inserisci l’ente o l’organizzazione che ha rilasciato il titolo.",
        "en": "Enter the body or organisation that issued the qualification.",
        "fr": "Indiquez l’organisme qui a délivré le titre.",
        "es": "Indica la entidad u organización que expidió el título.",
        "de": "Gib die Stelle oder Organisation an, die den Nachweis ausgestellt hat.",
        "ro": "Introdu instituția sau organizația care a emis titlul.",
        "uk": "Укажіть установу або організацію, яка видала документ.",
        "fil": "Ilagay ang institusyon o organisasyong nagbigay ng kwalipikasyon.",
    },
    "profile_card.confirm_delete": {
        "it": "Eliminare questa scheda? Il testo libero già presente resterà invariato.",
        "en": "Delete this card? The existing free-text content will remain unchanged.",
        "fr": "Supprimer cette fiche ? Le texte libre existant restera inchangé.",
        "es": "¿Eliminar esta ficha? El texto libre existente no se modificará.",
        "de": "Diese Profilkarte löschen? Der vorhandene Freitext bleibt unverändert.",
        "ro": "Ștergi această fișă? Textul liber existent va rămâne neschimbat.",
        "uk": "Видалити цю картку? Наявний довільний текст залишиться без змін.",
        "fil": "I-delete ang card na ito? Mananatiling hindi nagbabago ang kasalukuyang free text.",
    },
    "profile_card.error_existing": {
        "it": "Per questo campo esiste già una scheda. Aprila per modificarla.",
        "en": "A card already exists for this field. Open it to edit it.",
        "fr": "Une fiche existe déjà pour ce champ. Ouvrez-la pour la modifier.",
        "es": "Ya existe una ficha para este campo. Ábrela para editarla.",
        "de": "Für dieses Feld gibt es bereits eine Profilkarte. Öffne sie zum Bearbeiten.",
        "ro": "Există deja o fișă pentru acest câmp. Deschide-o pentru a o modifica.",
        "uk": "Для цього поля вже є картка. Відкрийте її, щоб відредагувати.",
        "fil": "May card na para sa field na ito. Buksan ito para i-edit.",
    },
    "profile_card.error_not_found": {
        "it": "Scheda non trovata.", "en": "Card not found.", "fr": "Fiche introuvable.",
        "es": "Ficha no encontrada.", "de": "Profilkarte nicht gefunden.", "ro": "Fișa nu a fost găsită.",
        "uk": "Картку не знайдено.", "fil": "Hindi makita ang card.",
    },
    "profile_card.error_checked": {
        "it": "Questa scheda è già stata controllata. Se modifichi i dati, il controllo verrà azzerato e potrai richiederlo di nuovo.",
        "en": "This card has already been checked. If you change its details, the check will be reset and you can request it again.",
        "fr": "Cette fiche a déjà été contrôlée. Si vous modifiez les données, le contrôle sera réinitialisé et vous pourrez le demander à nouveau.",
        "es": "Esta ficha ya se ha comprobado. Si modificas los datos, la comprobación se restablecerá y podrás solicitarla de nuevo.",
        "de": "Diese Profilkarte wurde bereits geprüft. Wenn du die Angaben änderst, wird die Prüfung zurückgesetzt und kann erneut angefordert werden.",
        "ro": "Această fișă a fost deja verificată. Dacă modifici datele, verificarea se va reseta și o vei putea solicita din nou.",
        "uk": "Цю картку вже перевірено. Якщо змінити дані, перевірку буде скинуто й її можна буде запросити знову.",
        "fil": "Nasuri na ang card na ito. Kapag binago mo ang detalye, mare-reset ang pagsusuri at maaari mo itong hilingin muli.",
    },
    "profile_card.error_unverifiable": {
        "it": "Questa scheda non è verificabile con i dati disponibili. Modifica i dati della scheda prima di richiedere un nuovo controllo.",
        "en": "This card cannot be checked with the available details. Update the card before requesting another check.",
        "fr": "Cette fiche ne peut pas être contrôlée avec les informations disponibles. Modifiez-la avant de demander un nouveau contrôle.",
        "es": "Esta ficha no puede comprobarse con los datos disponibles. Modifícala antes de solicitar otra comprobación.",
        "de": "Diese Profilkarte kann mit den verfügbaren Angaben nicht geprüft werden. Aktualisiere sie, bevor du eine neue Prüfung anforderst.",
        "ro": "Această fișă nu poate fi verificată cu datele disponibile. Modifică fișa înainte de a solicita o nouă verificare.",
        "uk": "Цю картку неможливо перевірити за наявними даними. Оновіть її, перш ніж подавати новий запит на перевірку.",
        "fil": "Hindi masuri ang card na ito gamit ang kasalukuyang detalye. I-update muna ang card bago humiling ng panibagong pagsusuri.",
    },
    "profile_card.error_changed": {
        "it": "La scheda è cambiata. Riaprila e riprova.",
        "en": "The card has changed. Reopen it and try again.",
        "fr": "La fiche a été modifiée. Rouvrez-la et réessayez.",
        "es": "La ficha ha cambiado. Vuelve a abrirla e inténtalo de nuevo.",
        "de": "Die Profilkarte wurde geändert. Öffne sie erneut und versuche es noch einmal.",
        "ro": "Fișa a fost modificată. Redeschide-o și încearcă din nou.",
        "uk": "Картку було змінено. Відкрийте її знову та повторіть спробу.",
        "fil": "Nabago ang card. Buksan itong muli at subukan ulit.",
    },
    "profile_card.error_expired": {
        "it": "La scheda è scaduta. Aggiorna prima la data di scadenza e poi richiedi un nuovo controllo.",
        "en": "The card has expired. Update the expiry date before requesting another check.",
        "fr": "La fiche a expiré. Mettez d’abord à jour la date d’expiration, puis demandez un nouveau contrôle.",
        "es": "La ficha ha caducado. Actualiza primero la fecha de caducidad y después solicita una nueva comprobación.",
        "de": "Die Profilkarte ist abgelaufen. Aktualisiere zuerst das Ablaufdatum und fordere dann eine neue Prüfung an.",
        "ro": "Fișa a expirat. Actualizează mai întâi data expirării, apoi solicită o nouă verificare.",
        "uk": "Термін дії картки минув. Спочатку оновіть дату завершення дії, а потім подайте новий запит на перевірку.",
        "fil": "Nag-expire na ang card. I-update muna ang expiry date bago humiling ng panibagong pagsusuri.",
    },
    "profile_card.error_acknowledgement": {
        "it": "Conferma di aver letto le informazioni sul controllo.",
        "en": "Confirm that you have read the check information.",
        "fr": "Confirmez avoir lu les informations relatives au contrôle.",
        "es": "Confirma que has leído la información sobre la comprobación.",
        "de": "Bestätige, dass du die Informationen zur Prüfung gelesen hast.",
        "ro": "Confirmă că ai citit informațiile despre verificare.",
        "uk": "Підтвердьте, що ви прочитали інформацію про перевірку.",
        "fil": "Kumpirmahing nabasa mo ang impormasyon tungkol sa pagsusuri.",
    },
    "profile_card.error_unavailable": {
        "it": "La funzione non è ancora disponibile o si è verificato un errore.",
        "en": "This feature is not available yet or an error occurred.",
        "fr": "Cette fonctionnalité n’est pas encore disponible ou une erreur s’est produite.",
        "es": "Esta función aún no está disponible o se ha producido un error.",
        "de": "Diese Funktion ist noch nicht verfügbar oder es ist ein Fehler aufgetreten.",
        "ro": "Funcția nu este încă disponibilă sau a apărut o eroare.",
        "uk": "Ця функція ще недоступна або сталася помилка.",
        "fil": "Hindi pa available ang feature na ito o nagkaroon ng error.",
    },
    "profile_card.error_request": {
        "it": "Richiesta non riuscita.", "en": "Request failed.", "fr": "Échec de la demande.",
        "es": "La solicitud ha fallado.", "de": "Anfrage fehlgeschlagen.",
        "ro": "Solicitarea a eșuat.", "uk": "Не вдалося надіслати запит.",
        "fil": "Hindi nagtagumpay ang request.",
    },
    "profile_card.error_certificate_limit": {
        "it": "Puoi avere al massimo 20 certificazioni attive.",
        "en": "You can have no more than 20 active certifications.",
        "fr": "Vous pouvez avoir au maximum 20 certifications actives.",
        "es": "Puedes tener un máximo de 20 certificaciones activas.",
        "de": "Du kannst höchstens 20 aktive Zertifizierungen haben.",
        "ro": "Poți avea cel mult 20 de certificări active.",
        "uk": "Можна мати не більше 20 активних сертифікацій.",
        "fil": "Maaari kang magkaroon ng hanggang 20 aktibong certification.",
    },
    "profile_card.error_request_rate_limit": {
        "it": "Hai inviato troppe richieste di controllo. Riprova tra un’ora.",
        "en": "You have sent too many check requests. Try again in one hour.",
        "fr": "Vous avez envoyé trop de demandes de contrôle. Réessayez dans une heure.",
        "es": "Has enviado demasiadas solicitudes de comprobación. Inténtalo de nuevo dentro de una hora.",
        "de": "Du hast zu viele Prüfanfragen gesendet. Versuche es in einer Stunde erneut.",
        "ro": "Ai trimis prea multe solicitări de verificare. Încearcă din nou peste o oră.",
        "uk": "Ви надіслали забагато запитів на перевірку. Спробуйте знову через годину.",
        "fil": "Masyado kang maraming ipinadalang request para sa pagsusuri. Subukan muli pagkalipas ng isang oras.",
    },
    "profile_card.error_invalid_data": {
        "it": "Controlla i dati inseriti e riprova.",
        "en": "Check the information entered and try again.",
        "fr": "Vérifiez les informations saisies et réessayez.",
        "es": "Comprueba los datos introducidos e inténtalo de nuevo.",
        "de": "Prüfe deine Angaben und versuche es erneut.",
        "ro": "Verifică datele introduse și încearcă din nou.",
        "uk": "Перевірте введені дані та спробуйте ще раз.",
        "fil": "Suriin ang inilagay na impormasyon at subukan muli.",
    },
    "profile_card.error_invalid_date": {
        "it": "Controlla le date inserite.", "en": "Check the dates entered.",
        "fr": "Vérifiez les dates saisies.", "es": "Comprueba las fechas introducidas.",
        "de": "Prüfe die eingegebenen Datumsangaben.", "ro": "Verifică datele introduse.",
        "uk": "Перевірте введені дати.", "fil": "Suriin ang mga inilagay na petsa.",
    },
    "profile_card.error_date_order": {
        "it": "La data finale non può precedere quella iniziale.",
        "en": "The end date cannot be before the start date.",
        "fr": "La date de fin ne peut pas précéder la date de début.",
        "es": "La fecha de finalización no puede ser anterior a la fecha de inicio.",
        "de": "Das Enddatum darf nicht vor dem Startdatum liegen.",
        "ro": "Data de încheiere nu poate fi anterioară datei de început.",
        "uk": "Дата завершення не може передувати даті початку.",
        "fil": "Hindi maaaring mauna ang petsa ng pagtatapos sa petsa ng simula.",
    },
    "availability.title": {
        "it": "Disponibilità per i servizi",
        "en": "Availability for services",
        "fr": "Disponibilité pour les services",
        "es": "Disponibilidad para los servicios",
        "de": "Verfügbarkeit für Dienstleistungen",
        "ro": "Disponibilitate pentru servicii",
        "uk": "Доступність для надання послуг",
        "fil": "Availability para sa mga serbisyo",
    },
    "availability.private_subtitle": {
        "it": "Indica quando sei disponibile a svolgere i servizi che offri.",
        "en": "Show when you are available to provide the services you offer.",
        "fr": "Indiquez quand vous êtes disponible pour assurer les services que vous proposez.",
        "es": "Indica cuándo estás disponible para prestar los servicios que ofreces.",
        "de": "Gib an, wann du die von dir angebotenen Dienstleistungen erbringen kannst.",
        "ro": "Indică atunci când ești disponibil să prestezi serviciile pe care le oferi.",
        "uk": "Зазначте, коли ви можете надавати запропоновані вами послуги.",
        "fil": "Ilagay kung kailan ka available para sa mga serbisyong inaalok mo.",
    },
    "availability.public_subtitle": {
        "it": "Quando questa persona è disponibile a svolgere i servizi offerti.",
        "en": "When this person is available to provide the services offered.",
        "fr": "Quand cette personne est disponible pour assurer les services proposés.",
        "es": "Cuándo está disponible esta persona para prestar los servicios ofrecidos.",
        "de": "Wann diese Person die angebotenen Dienstleistungen erbringen kann.",
        "ro": "Când este disponibilă această persoană pentru a presta serviciile oferite.",
        "uk": "Коли ця людина може надавати запропоновані послуги.",
        "fil": "Kung kailan available ang taong ito para sa mga inaalok na serbisyo.",
    },
    "availability.setup": {
        "it": "Imposta", "en": "Set up", "fr": "Configurer",
        "es": "Configurar", "de": "Einrichten", "ro": "Configurează",
        "uk": "Налаштувати", "fil": "I-set up",
    },
    "availability.edit": {
        "it": "Modifica", "en": "Edit", "fr": "Modifier",
        "es": "Editar", "de": "Bearbeiten", "ro": "Modifică",
        "uk": "Змінити", "fil": "I-edit",
    },
    "availability.reconfirm": {
        "it": "Riconferma", "en": "Reconfirm", "fr": "Reconfirmer",
        "es": "Volver a confirmar", "de": "Erneut bestätigen",
        "ro": "Reconfirmă", "uk": "Підтвердити знову", "fil": "Kumpirmahing muli",
    },
    "availability.reconfirmed": {
        "it": "Disponibilità riconfermata.",
        "en": "Availability reconfirmed.",
        "fr": "Disponibilité reconfirmée.",
        "es": "Disponibilidad confirmada de nuevo.",
        "de": "Verfügbarkeit erneut bestätigt.",
        "ro": "Disponibilitate reconfirmată.",
        "uk": "Доступність підтверджено повторно.",
        "fil": "Muling nakumpirma ang availability.",
    },
    "availability.not_configured": {
        "it": "Disponibilità non ancora impostata",
        "en": "Availability not set yet",
        "fr": "Disponibilité pas encore renseignée",
        "es": "Disponibilidad aún no configurada",
        "de": "Verfügbarkeit noch nicht angegeben",
        "ro": "Disponibilitatea nu este încă setată",
        "uk": "Доступність ще не налаштована",
        "fil": "Hindi pa naka-set ang availability",
    },
    "availability.unavailable_feature": {
        "it": "La funzione disponibilità non è al momento accessibile. Riprova tra poco.",
        "en": "The availability feature is not accessible right now. Please try again shortly.",
        "fr": "La fonction de disponibilité n’est pas accessible pour le moment. Réessayez dans quelques instants.",
        "es": "La función de disponibilidad no está accesible en este momento. Inténtalo de nuevo en breve.",
        "de": "Die Verfügbarkeitsfunktion ist derzeit nicht erreichbar. Versuche es gleich noch einmal.",
        "ro": "Funcția de disponibilitate nu este accesibilă momentan. Încearcă din nou în scurt timp.",
        "uk": "Функція доступності зараз недоступна. Спробуйте ще раз трохи пізніше.",
        "fil": "Hindi ma-access ngayon ang availability feature. Subukan muli maya-maya.",
    },
    "availability.overall_status": {
        "it": "Disponibilità generale", "en": "Overall availability",
        "fr": "Disponibilité générale", "es": "Disponibilidad general",
        "de": "Allgemeine Verfügbarkeit", "ro": "Disponibilitate generală",
        "uk": "Загальна доступність", "fil": "Pangkalahatang availability",
    },
    "availability.status_available": {
        "it": "Disponibile", "en": "Available", "fr": "Disponible",
        "es": "Disponible", "de": "Verfügbar", "ro": "Disponibil",
        "uk": "Доступний(-а)", "fil": "Available",
    },
    "availability.status_available_description": {
        "it": "Sono disponibile nelle fasce indicate.",
        "en": "I am available during the times shown.",
        "fr": "Je suis disponible aux créneaux indiqués.",
        "es": "Estoy disponible en las franjas indicadas.",
        "de": "Ich bin zu den angegebenen Zeiten verfügbar.",
        "ro": "Sunt disponibil în intervalele indicate.",
        "uk": "Я доступний(-а) у зазначені проміжки часу.",
        "fil": "Available ako sa mga nakasaad na oras.",
    },
    "availability.status_limited": {
        "it": "Disponibilità limitata", "en": "Limited availability",
        "fr": "Disponibilité limitée", "es": "Disponibilidad limitada",
        "de": "Eingeschränkt verfügbar", "ro": "Disponibilitate limitată",
        "uk": "Обмежена доступність", "fil": "Limitadong availability",
    },
    "availability.status_limited_description": {
        "it": "Sono disponibile solo in alcuni giorni o periodi.",
        "en": "I am available only on certain days or during certain periods.",
        "fr": "Je suis disponible uniquement certains jours ou à certaines périodes.",
        "es": "Solo estoy disponible determinados días o períodos.",
        "de": "Ich bin nur an bestimmten Tagen oder in bestimmten Zeiträumen verfügbar.",
        "ro": "Sunt disponibil doar în anumite zile sau perioade.",
        "uk": "Я доступний(-а) лише в окремі дні або періоди.",
        "fil": "Available lamang ako sa ilang araw o panahon.",
    },
    "availability.status_unavailable": {
        "it": "Non disponibile", "en": "Unavailable", "fr": "Indisponible",
        "es": "No disponible", "de": "Nicht verfügbar", "ro": "Indisponibil",
        "uk": "Недоступний(-а)", "fil": "Hindi available",
    },
    "availability.status_unavailable_description": {
        "it": "Al momento non sono disponibile a svolgere servizi.",
        "en": "I am not currently available to provide services.",
        "fr": "Je ne suis pas disponible actuellement pour assurer des services.",
        "es": "Actualmente no estoy disponible para prestar servicios.",
        "de": "Derzeit kann ich keine Dienstleistungen erbringen.",
        "ro": "Momentan nu sunt disponibil pentru a presta servicii.",
        "uk": "Наразі я не можу надавати послуги.",
        "fil": "Hindi ako available ngayon para magbigay ng serbisyo.",
    },
    "availability.weekly_title": {
        "it": "Disponibilità settimanale", "en": "Weekly availability",
        "fr": "Disponibilité hebdomadaire", "es": "Disponibilidad semanal",
        "de": "Wöchentliche Verfügbarkeit", "ro": "Disponibilitate săptămânală",
        "uk": "Щотижнева доступність", "fil": "Lingguhang availability",
    },
    "availability.weekly_help": {
        "it": "Seleziona per ogni giorno le fasce in cui puoi svolgere i servizi.",
        "en": "For each day, select the times when you can provide services.",
        "fr": "Pour chaque jour, sélectionnez les créneaux où vous pouvez assurer les services.",
        "es": "Selecciona para cada día las franjas en las que puedes prestar servicios.",
        "de": "Wähle für jeden Tag die Zeiten aus, zu denen du Dienstleistungen erbringen kannst.",
        "ro": "Selectează pentru fiecare zi intervalele în care poți presta servicii.",
        "uk": "Для кожного дня виберіть час, коли ви можете надавати послуги.",
        "fil": "Piliin sa bawat araw ang mga oras kung kailan ka makakapagbigay ng serbisyo.",
    },
    "availability.slot_morning": {
        "it": "Mattina", "en": "Morning", "fr": "Matin", "es": "Mañana",
        "de": "Vormittag", "ro": "Dimineața", "uk": "Ранок", "fil": "Umaga",
    },
    "availability.slot_afternoon": {
        "it": "Pomeriggio", "en": "Afternoon", "fr": "Après-midi",
        "es": "Tarde", "de": "Nachmittag", "ro": "După-amiaza",
        "uk": "День", "fil": "Hapon",
    },
    "availability.slot_evening": {
        "it": "Sera", "en": "Evening", "fr": "Soir", "es": "Noche",
        "de": "Abend", "ro": "Seara", "uk": "Вечір", "fil": "Gabi",
    },
    "availability.slot_night": {
        "it": "Notte", "en": "Night", "fr": "Nuit", "es": "Madrugada",
        "de": "Nacht", "ro": "Noaptea", "uk": "Ніч", "fil": "Magdamag",
    },
    "availability.day_monday": {
        "it": "Lunedì", "en": "Monday", "fr": "Lundi", "es": "Lunes",
        "de": "Montag", "ro": "Luni", "uk": "Понеділок", "fil": "Lunes",
    },
    "availability.day_tuesday": {
        "it": "Martedì", "en": "Tuesday", "fr": "Mardi", "es": "Martes",
        "de": "Dienstag", "ro": "Marți", "uk": "Вівторок", "fil": "Martes",
    },
    "availability.day_wednesday": {
        "it": "Mercoledì", "en": "Wednesday", "fr": "Mercredi", "es": "Miércoles",
        "de": "Mittwoch", "ro": "Miercuri", "uk": "Середа", "fil": "Miyerkules",
    },
    "availability.day_thursday": {
        "it": "Giovedì", "en": "Thursday", "fr": "Jeudi", "es": "Jueves",
        "de": "Donnerstag", "ro": "Joi", "uk": "Четвер", "fil": "Huwebes",
    },
    "availability.day_friday": {
        "it": "Venerdì", "en": "Friday", "fr": "Vendredi", "es": "Viernes",
        "de": "Freitag", "ro": "Vineri", "uk": "П’ятниця", "fil": "Biyernes",
    },
    "availability.day_saturday": {
        "it": "Sabato", "en": "Saturday", "fr": "Samedi", "es": "Sábado",
        "de": "Samstag", "ro": "Sâmbătă", "uk": "Субота", "fil": "Sabado",
    },
    "availability.day_sunday": {
        "it": "Domenica", "en": "Sunday", "fr": "Dimanche", "es": "Domingo",
        "de": "Sonntag", "ro": "Duminică", "uk": "Неділя", "fil": "Linggo",
    },
    "availability.day_monday_short": {
        "it": "Lun", "en": "Mon", "fr": "Lun", "es": "Lun", "de": "Mo",
        "ro": "Lu", "uk": "Пн", "fil": "Lun",
    },
    "availability.day_tuesday_short": {
        "it": "Mar", "en": "Tue", "fr": "Mar", "es": "Mar", "de": "Di",
        "ro": "Ma", "uk": "Вт", "fil": "Mar",
    },
    "availability.day_wednesday_short": {
        "it": "Mer", "en": "Wed", "fr": "Mer", "es": "Mié", "de": "Mi",
        "ro": "Mi", "uk": "Ср", "fil": "Miy",
    },
    "availability.day_thursday_short": {
        "it": "Gio", "en": "Thu", "fr": "Jeu", "es": "Jue", "de": "Do",
        "ro": "Jo", "uk": "Чт", "fil": "Huw",
    },
    "availability.day_friday_short": {
        "it": "Ven", "en": "Fri", "fr": "Ven", "es": "Vie", "de": "Fr",
        "ro": "Vi", "uk": "Пт", "fil": "Biy",
    },
    "availability.day_saturday_short": {
        "it": "Sab", "en": "Sat", "fr": "Sam", "es": "Sáb", "de": "Sa",
        "ro": "Sâ", "uk": "Сб", "fil": "Sab",
    },
    "availability.day_sunday_short": {
        "it": "Dom", "en": "Sun", "fr": "Dim", "es": "Dom", "de": "So",
        "ro": "Du", "uk": "Нд", "fil": "Lin",
    },
    "availability.special_title": {
        "it": "Date particolari", "en": "Special dates", "fr": "Dates particulières",
        "es": "Fechas especiales", "de": "Besondere Tage", "ro": "Date speciale",
        "uk": "Особливі дати", "fil": "Mga espesyal na petsa",
    },
    "availability.special_help": {
        "it": "Aggiungi eccezioni alla disponibilità settimanale per date specifiche.",
        "en": "Add exceptions to your weekly availability for specific dates.",
        "fr": "Ajoutez des exceptions à votre disponibilité hebdomadaire pour des dates précises.",
        "es": "Añade excepciones a tu disponibilidad semanal para fechas concretas.",
        "de": "Füge für bestimmte Daten Ausnahmen von deiner wöchentlichen Verfügbarkeit hinzu.",
        "ro": "Adaugă excepții de la disponibilitatea săptămânală pentru anumite date.",
        "uk": "Додайте винятки до щотижневої доступності для окремих дат.",
        "fil": "Magdagdag ng mga exception sa lingguhang availability para sa partikular na petsa.",
    },
    "availability.add_special": {
        "it": "Aggiungi data", "en": "Add date", "fr": "Ajouter une date",
        "es": "Añadir fecha", "de": "Datum hinzufügen", "ro": "Adaugă o dată",
        "uk": "Додати дату", "fil": "Magdagdag ng petsa",
    },
    "availability.special_available": {
        "it": "Disponibile", "en": "Available", "fr": "Disponible",
        "es": "Disponible", "de": "Verfügbar", "ro": "Disponibil",
        "uk": "Доступний(-а)", "fil": "Available",
    },
    "availability.special_unavailable": {
        "it": "Non disponibile", "en": "Unavailable", "fr": "Indisponible",
        "es": "No disponible", "de": "Nicht verfügbar", "ro": "Indisponibil",
        "uk": "Недоступний(-а)", "fil": "Hindi available",
    },
    "availability.date": {
        "it": "Data", "en": "Date", "fr": "Date", "es": "Fecha",
        "de": "Datum", "ro": "Data", "uk": "Дата", "fil": "Petsa",
    },
    "availability.remove": {
        "it": "Rimuovi", "en": "Remove", "fr": "Supprimer", "es": "Eliminar",
        "de": "Entfernen", "ro": "Elimină", "uk": "Видалити", "fil": "Alisin",
    },
    "availability.absences_title": {
        "it": "Periodi non disponibili", "en": "Unavailable periods", "fr": "Périodes indisponibles",
        "es": "Períodos no disponibles", "de": "Nicht verfügbare Zeiträume",
        "ro": "Perioade indisponibile", "uk": "Періоди недоступності", "fil": "Mga panahong hindi available",
    },
    "availability.absences_help": {
        "it": "Indica solo le date in cui non puoi svolgere servizi.",
        "en": "Only add dates when you cannot provide services.",
        "fr": "Indiquez uniquement les dates auxquelles vous ne pouvez pas assurer de services.",
        "es": "Indica solo las fechas en las que no puedes prestar servicios.",
        "de": "Gib nur Zeiträume an, in denen du keine Dienstleistungen erbringen kannst.",
        "ro": "Indică doar datele în care nu poți presta servicii.",
        "uk": "Зазначайте лише дати, коли ви не можете надавати послуги.",
        "fil": "Ilagay lamang ang mga petsang hindi ka makakapagbigay ng serbisyo.",
    },
    "availability.add_absence": {
        "it": "Aggiungi periodo", "en": "Add unavailable period", "fr": "Ajouter une période",
        "es": "Añadir período", "de": "Zeitraum hinzufügen", "ro": "Adaugă o perioadă",
        "uk": "Додати період", "fil": "Magdagdag ng panahon",
    },
    "availability.start": {
        "it": "Inizio", "en": "Start", "fr": "Début", "es": "Inicio",
        "de": "Beginn", "ro": "Început", "uk": "Початок", "fil": "Simula",
    },
    "availability.end": {
        "it": "Fine", "en": "End", "fr": "Fin", "es": "Fin",
        "de": "Ende", "ro": "Sfârșit", "uk": "Завершення", "fil": "Wakas",
    },
    "availability.save": {
        "it": "Salva disponibilità", "en": "Save availability",
        "fr": "Enregistrer la disponibilité", "es": "Guardar disponibilidad",
        "de": "Verfügbarkeit speichern", "ro": "Salvează disponibilitatea",
        "uk": "Зберегти доступність", "fil": "I-save ang availability",
    },
    "availability.saving": {
        "it": "Salvataggio...", "en": "Saving...", "fr": "Enregistrement...",
        "es": "Guardando...", "de": "Wird gespeichert...", "ro": "Se salvează...",
        "uk": "Збереження...", "fil": "Sine-save...",
    },
    "availability.saved": {
        "it": "Disponibilità salvata.", "en": "Availability saved.",
        "fr": "Disponibilité enregistrée.", "es": "Disponibilidad guardada.",
        "de": "Verfügbarkeit gespeichert.", "ro": "Disponibilitate salvată.",
        "uk": "Доступність збережено.", "fil": "Na-save ang availability.",
    },
    "availability.close": {
        "it": "Chiudi", "en": "Close", "fr": "Fermer", "es": "Cerrar",
        "de": "Schließen", "ro": "Închide", "uk": "Закрити", "fil": "Isara",
    },
    "availability.error_generic": {
        "it": "Impossibile salvare la disponibilità. Riprova tra poco.",
        "en": "Unable to save availability. Please try again shortly.",
        "fr": "Impossible d’enregistrer la disponibilité. Réessayez dans quelques instants.",
        "es": "No se ha podido guardar la disponibilidad. Inténtalo de nuevo en breve.",
        "de": "Die Verfügbarkeit konnte nicht gespeichert werden. Versuche es gleich noch einmal.",
        "ro": "Disponibilitatea nu a putut fi salvată. Încearcă din nou în scurt timp.",
        "uk": "Не вдалося зберегти доступність. Спробуйте ще раз трохи пізніше.",
        "fil": "Hindi ma-save ang availability. Subukan muli maya-maya.",
    },
    "availability.error_select_slot": {
        "it": "Seleziona almeno una fascia per ogni data indicata come disponibile.",
        "en": "Select at least one time for every date marked as available.",
        "fr": "Sélectionnez au moins un créneau pour chaque date indiquée comme disponible.",
        "es": "Selecciona al menos una franja para cada fecha marcada como disponible.",
        "de": "Wähle für jedes als verfügbar markierte Datum mindestens eine Zeit aus.",
        "ro": "Selectează cel puțin un interval pentru fiecare dată marcată ca disponibilă.",
        "uk": "Виберіть принаймні один проміжок часу для кожної дати, позначеної як доступна.",
        "fil": "Pumili ng kahit isang oras para sa bawat petsang minarkahang available.",
    },
    "availability.freshness_current": {
        "it": "Disponibilità aggiornata", "en": "Availability up to date",
        "fr": "Disponibilité à jour", "es": "Disponibilidad actualizada",
        "de": "Verfügbarkeit aktuell", "ro": "Disponibilitate actualizată",
        "uk": "Доступність актуальна", "fil": "Updated ang availability",
    },
    "availability.freshness_due": {
        "it": "Da riconfermare", "en": "Reconfirmation due", "fr": "À reconfirmer",
        "es": "Pendiente de confirmación", "de": "Erneut zu bestätigen",
        "ro": "Necesită reconfirmare", "uk": "Потрібне повторне підтвердження",
        "fil": "Kailangang kumpirmahing muli",
    },
    "availability.freshness_old": {
        "it": "Disponibilità non recente", "en": "Availability not recent",
        "fr": "Disponibilité non récente", "es": "Disponibilidad no reciente",
        "de": "Verfügbarkeit nicht aktuell", "ro": "Disponibilitate neactualizată",
        "uk": "Доступність давно не оновлювалася", "fil": "Hindi na bago ang availability",
    },
    "availability.public_confirmed": {
        "it": "Disponibilità confermata", "en": "Availability confirmed",
        "fr": "Disponibilité confirmée", "es": "Disponibilidad confirmada",
        "de": "Verfügbarkeit bestätigt", "ro": "Disponibilitate confirmată",
        "uk": "Доступність підтверджено", "fil": "Nakumpirma ang availability",
    },
    "availability.applies_all_services": {
        "it": "Vale per tutti i servizi offerti.",
        "en": "Applies to all services offered.",
        "fr": "S’applique à tous les services proposés.",
        "es": "Se aplica a todos los servicios ofrecidos.",
        "de": "Gilt für alle angebotenen Dienstleistungen.",
        "ro": "Se aplică tuturor serviciilor oferite.",
        "uk": "Стосується всіх запропонованих послуг.",
        "fil": "Para sa lahat ng inaalok na serbisyo.",
    },
    "availability.no_weekly": {
        "it": "Nessuna fascia settimanale indicata.",
        "en": "No weekly times provided.",
        "fr": "Aucun créneau hebdomadaire indiqué.",
        "es": "No se ha indicado ninguna franja semanal.",
        "de": "Keine wöchentlichen Zeiten angegeben.",
        "ro": "Nu a fost indicat niciun interval săptămânal.",
        "uk": "Щотижневий час не вказано.",
        "fil": "Walang lingguhang oras na inilagay.",
    },
    "availability.weekly_slots": {
        "it": "Fasce settimanali: {count}", "en": "Weekly times: {count}",
        "fr": "Créneaux hebdomadaires : {count}", "es": "Franjas semanales: {count}",
        "de": "Wöchentliche Zeiten: {count}", "ro": "Intervale săptămânale: {count}",
        "uk": "Щотижневі проміжки: {count}", "fil": "Lingguhang oras: {count}",
    },
    "availability.view_schedule": {
        "it": "Vedi disponibilità", "en": "View availability",
        "fr": "Voir les disponibilités", "es": "Ver disponibilidad",
        "de": "Verfügbarkeit ansehen", "ro": "Vezi disponibilitatea",
        "uk": "Переглянути доступність", "fil": "Tingnan ang availability",
    },
    "availability.exceptions_count": {
        "it": "Date particolari: {count}", "en": "Special dates: {count}",
        "fr": "Dates particulières : {count}", "es": "Fechas especiales: {count}",
        "de": "Besondere Tage: {count}", "ro": "Date speciale: {count}",
        "uk": "Особливі дати: {count}", "fil": "Mga espesyal na petsa: {count}",
    },
    "availability.absences_count": {
        "it": "Periodi di assenza: {count}", "en": "Periods away: {count}",
        "fr": "Périodes d’absence : {count}", "es": "Períodos de ausencia: {count}",
        "de": "Abwesenheitszeiträume: {count}", "ro": "Perioade de absență: {count}",
        "uk": "Періоди відсутності: {count}", "fil": "Mga panahon ng pagliban: {count}",
    },
    "availability.add_special_date": {
        "it": "Aggiungi data particolare", "en": "Add special date",
        "fr": "Ajouter une date particulière", "es": "Añadir fecha especial",
        "de": "Besonderen Tag hinzufügen", "ro": "Adaugă o dată specială",
        "uk": "Додати особливу дату", "fil": "Magdagdag ng espesyal na petsa",
    },
    "availability.cancel": {
        "it": "Annulla", "en": "Cancel", "fr": "Annuler", "es": "Cancelar",
        "de": "Abbrechen", "ro": "Anulează", "uk": "Скасувати", "fil": "Kanselahin",
    },
    "availability.confirm": {
        "it": "Conferma", "en": "Confirm", "fr": "Confirmer", "es": "Confirmar",
        "de": "Bestätigen", "ro": "Confirmă", "uk": "Підтвердити", "fil": "Kumpirmahin",
    },
    "availability.confirming": {
        "it": "Conferma...", "en": "Confirming...", "fr": "Confirmation...",
        "es": "Confirmando...", "de": "Wird bestätigt...", "ro": "Se confirmă...",
        "uk": "Підтвердження...", "fil": "Kinukumpirma...",
    },
    "availability.dialog_eyebrow": {
        "it": "DISPONIBILITÀ SERVIZI", "en": "SERVICE AVAILABILITY",
        "fr": "DISPONIBILITÉ POUR LES SERVICES", "es": "DISPONIBILIDAD PARA SERVICIOS",
        "de": "VERFÜGBARKEIT FÜR DIENSTLEISTUNGEN", "ro": "DISPONIBILITATE PENTRU SERVICII",
        "uk": "ДОСТУПНІСТЬ ДЛЯ НАДАННЯ ПОСЛУГ", "fil": "AVAILABILITY PARA SA MGA SERBISYO",
    },
    "availability.dialog_subtitle": {
        "it": "Aggiorna giorni, fasce ed eccezioni per tutti i servizi che offri.",
        "en": "Update days, times and exceptions for all the services you offer.",
        "fr": "Mettez à jour les jours, les créneaux et les exceptions pour tous les services que vous proposez.",
        "es": "Actualiza días, franjas y excepciones para todos los servicios que ofreces.",
        "de": "Aktualisiere Tage, Zeiten und Ausnahmen für alle von dir angebotenen Dienstleistungen.",
        "ro": "Actualizează zilele, intervalele și excepțiile pentru toate serviciile pe care le oferi.",
        "uk": "Оновіть дні, час і винятки для всіх послуг, які ви пропонуєте.",
        "fil": "I-update ang mga araw, oras, at exception para sa lahat ng serbisyong inaalok mo.",
    },
    "availability.dialog_title": {
        "it": "Quando sei disponibile?", "en": "When are you available?",
        "fr": "Quand êtes-vous disponible ?", "es": "¿Cuándo estás disponible?",
        "de": "Wann bist du verfügbar?", "ro": "Când ești disponibil?",
        "uk": "Коли ви доступні?", "fil": "Kailan ka available?",
    },
    "availability.empty_absences": {
        "it": "Nessun periodo non disponibile aggiunto.",
        "en": "No unavailable periods added.",
        "fr": "Aucune période indisponible ajoutée.",
        "es": "No se ha añadido ningún período no disponible.",
        "de": "Keine nicht verfügbaren Zeiträume hinzugefügt.",
        "ro": "Nu a fost adăugată nicio perioadă indisponibilă.",
        "uk": "Періоди недоступності не додано.",
        "fil": "Wala pang idinagdag na panahong hindi available.",
    },
    "availability.empty_special_dates": {
        "it": "Nessuna data particolare aggiunta.",
        "en": "No special dates added.",
        "fr": "Aucune date particulière ajoutée.",
        "es": "No se ha añadido ninguna fecha especial.",
        "de": "Keine besonderen Tage hinzugefügt.",
        "ro": "Nu a fost adăugată nicio dată specială.",
        "uk": "Особливі дати не додано.",
        "fil": "Wala pang idinagdag na espesyal na petsa.",
    },
    "availability.error_date_order": {
        "it": "La data finale non può precedere quella iniziale.",
        "en": "The end date cannot be before the start date.",
        "fr": "La date de fin ne peut pas précéder la date de début.",
        "es": "La fecha final no puede ser anterior a la inicial.",
        "de": "Das Enddatum darf nicht vor dem Startdatum liegen.",
        "ro": "Data de încheiere nu poate fi anterioară datei de început.",
        "uk": "Дата завершення не може передувати даті початку.",
        "fil": "Hindi maaaring mauna ang petsa ng pagtatapos sa petsa ng simula.",
    },
    "availability.error_date_required": {
        "it": "Inserisci una data.", "en": "Enter a date.",
        "fr": "Saisissez une date.", "es": "Introduce una fecha.",
        "de": "Gib ein Datum ein.", "ro": "Introdu o dată.",
        "uk": "Вкажіть дату.", "fil": "Maglagay ng petsa.",
    },
    "availability.error_duplicate_date": {
        "it": "Questa data è già presente.", "en": "This date has already been added.",
        "fr": "Cette date a déjà été ajoutée.", "es": "Esta fecha ya se ha añadido.",
        "de": "Dieses Datum wurde bereits hinzugefügt.", "ro": "Această dată a fost deja adăugată.",
        "uk": "Цю дату вже додано.", "fil": "Naidagdag na ang petsang ito.",
    },
    "availability.error_invalid_data": {
        "it": "Controlla i dati inseriti e riprova.",
        "en": "Check the information entered and try again.",
        "fr": "Vérifiez les informations saisies et réessayez.",
        "es": "Comprueba los datos introducidos e inténtalo de nuevo.",
        "de": "Prüfe deine Angaben und versuche es erneut.",
        "ro": "Verifică datele introduse și încearcă din nou.",
        "uk": "Перевірте введені дані та спробуйте ще раз.",
        "fil": "Suriin ang inilagay na impormasyon at subukan muli.",
    },
    "availability.error_load": {
        "it": "Impossibile caricare la disponibilità. Riprova tra poco.",
        "en": "Unable to load availability. Please try again shortly.",
        "fr": "Impossible de charger la disponibilité. Réessayez dans quelques instants.",
        "es": "No se ha podido cargar la disponibilidad. Inténtalo de nuevo en breve.",
        "de": "Die Verfügbarkeit konnte nicht geladen werden. Versuche es gleich noch einmal.",
        "ro": "Disponibilitatea nu a putut fi încărcată. Încearcă din nou în scurt timp.",
        "uk": "Не вдалося завантажити доступність. Спробуйте ще раз трохи пізніше.",
        "fil": "Hindi ma-load ang availability. Subukan muli maya-maya.",
    },
    "availability.error_save": {
        "it": "Impossibile salvare la disponibilità. Riprova tra poco.",
        "en": "Unable to save availability. Please try again shortly.",
        "fr": "Impossible d’enregistrer la disponibilité. Réessayez dans quelques instants.",
        "es": "No se ha podido guardar la disponibilidad. Inténtalo de nuevo en breve.",
        "de": "Die Verfügbarkeit konnte nicht gespeichert werden. Versuche es gleich noch einmal.",
        "ro": "Disponibilitatea nu a putut fi salvată. Încearcă din nou în scurt timp.",
        "uk": "Не вдалося зберегти доступність. Спробуйте ще раз трохи пізніше.",
        "fil": "Hindi ma-save ang availability. Subukan muli maya-maya.",
    },
    "availability.error_special_slots": {
        "it": "Seleziona almeno una fascia per ogni data indicata come disponibile.",
        "en": "Select at least one time for every date marked as available.",
        "fr": "Sélectionnez au moins un créneau pour chaque date indiquée comme disponible.",
        "es": "Selecciona al menos una franja para cada fecha marcada como disponible.",
        "de": "Wähle für jedes als verfügbar markierte Datum mindestens eine Zeit aus.",
        "ro": "Selectează cel puțin un interval pentru fiecare dată marcată ca disponibilă.",
        "uk": "Виберіть принаймні один проміжок часу для кожної дати, позначеної як доступна.",
        "fil": "Pumili ng kahit isang oras para sa bawat petsang minarkahang available.",
    },
    "availability.from": {
        "it": "Dal", "en": "From", "fr": "Du", "es": "Desde",
        "de": "Von", "ro": "De la", "uk": "Від", "fil": "Mula",
    },
    "availability.loading": {
        "it": "Caricamento disponibilità...", "en": "Loading availability...",
        "fr": "Chargement de la disponibilité...", "es": "Cargando disponibilidad...",
        "de": "Verfügbarkeit wird geladen...", "ro": "Se încarcă disponibilitatea...",
        "uk": "Завантаження доступності...", "fil": "Nilo-load ang availability...",
    },
    "availability.overall_help": {
        "it": "Scegli lo stato che descrive la tua disponibilità attuale a svolgere servizi.",
        "en": "Choose the status that describes your current availability to provide services.",
        "fr": "Choisissez le statut qui décrit votre disponibilité actuelle pour assurer des services.",
        "es": "Elige el estado que describe tu disponibilidad actual para prestar servicios.",
        "de": "Wähle den Status, der deine aktuelle Verfügbarkeit für Dienstleistungen beschreibt.",
        "ro": "Alege starea care descrie disponibilitatea ta actuală pentru prestarea serviciilor.",
        "uk": "Оберіть статус, що описує вашу поточну доступність для надання послуг.",
        "fil": "Piliin ang status na naglalarawan ng kasalukuyan mong availability para magbigay ng serbisyo.",
    },
    "availability.slots": {
        "it": "Fasce", "en": "Times", "fr": "Créneaux", "es": "Franjas",
        "de": "Zeiten", "ro": "Intervale", "uk": "Проміжки часу", "fil": "Mga oras",
    },
    "availability.special_date": {
        "it": "Data particolare", "en": "Special date", "fr": "Date particulière",
        "es": "Fecha especial", "de": "Besonderer Tag", "ro": "Dată specială",
        "uk": "Особлива дата", "fil": "Espesyal na petsa",
    },
    "availability.special_dates_help": {
        "it": "Aggiungi eccezioni alla disponibilità settimanale per date specifiche.",
        "en": "Add exceptions to your weekly availability for specific dates.",
        "fr": "Ajoutez des exceptions à votre disponibilité hebdomadaire pour des dates précises.",
        "es": "Añade excepciones a tu disponibilidad semanal para fechas concretas.",
        "de": "Füge für bestimmte Daten Ausnahmen von deiner wöchentlichen Verfügbarkeit hinzu.",
        "ro": "Adaugă excepții de la disponibilitatea săptămânală pentru anumite date.",
        "uk": "Додайте винятки до щотижневої доступності для окремих дат.",
        "fil": "Magdagdag ng mga exception sa lingguhang availability para sa partikular na petsa.",
    },
    "availability.special_dates_title": {
        "it": "Date particolari", "en": "Special dates", "fr": "Dates particulières",
        "es": "Fechas especiales", "de": "Besondere Tage", "ro": "Date speciale",
        "uk": "Особливі дати", "fil": "Mga espesyal na petsa",
    },
    "availability.to": {
        "it": "Al", "en": "To", "fr": "Au", "es": "Hasta",
        "de": "Bis", "ro": "Până la", "uk": "До", "fil": "Hanggang",
    },
    "availability.type": {
        "it": "Tipo", "en": "Type", "fr": "Type", "es": "Tipo",
        "de": "Art", "ro": "Tip", "uk": "Тип", "fil": "Uri",
    },
    "availability.scope_all_services": {
        "it": "Tutti i servizi", "en": "All services",
        "fr": "Tous les services", "es": "Todos los servicios",
        "de": "Alle Dienstleistungen", "ro": "Toate serviciile",
        "uk": "Усі послуги", "fil": "Lahat ng serbisyo",
    },
    "availability.card_available_on": {
        "it": "Disponibile · confermata il {date}", "en": "Available · confirmed on {date}",
        "fr": "Disponible · confirmée le {date}", "es": "Disponible · confirmada el {date}",
        "de": "Verfügbar · bestätigt am {date}", "ro": "Disponibil · confirmat la {date}",
        "uk": "Доступно · підтверджено {date}", "fil": "Available · kinumpirma noong {date}",
    },
    "availability.card_limited_on": {
        "it": "Disponibilità limitata · confermata il {date}", "en": "Limited availability · confirmed on {date}",
        "fr": "Disponibilité limitée · confirmée le {date}", "es": "Disponibilidad limitada · confirmada el {date}",
        "de": "Eingeschränkt verfügbar · bestätigt am {date}", "ro": "Disponibilitate limitată · confirmată la {date}",
        "uk": "Обмежена доступність · підтверджено {date}", "fil": "Limitadong availability · kinumpirma noong {date}",
    },
    "availability.card_unavailable_on": {
        "it": "Non disponibile · confermata il {date}", "en": "Unavailable · confirmed on {date}",
        "fr": "Indisponible · confirmée le {date}", "es": "No disponible · confirmada el {date}",
        "de": "Nicht verfügbar · bestätigt am {date}", "ro": "Indisponibil · confirmat la {date}",
        "uk": "Недоступно · підтверджено {date}", "fil": "Hindi available · kinumpirma noong {date}",
    },
    "availability.card_expired": {
        "it": "Disponibilità da riconfermare", "en": "Availability needs reconfirmation",
        "fr": "Disponibilité à reconfirmer", "es": "Disponibilidad pendiente de reconfirmación",
        "de": "Verfügbarkeit erneut zu bestätigen", "ro": "Disponibilitate de reconfirmat",
        "uk": "Доступність потребує повторного підтвердження", "fil": "Kailangang kumpirmahing muli ang availability",
    },
    "availability.card_never_confirmed": {
        "it": "Disponibilità da confermare", "en": "Availability not yet confirmed",
        "fr": "Disponibilité non confirmée", "es": "Disponibilidad aún no confirmada",
        "de": "Verfügbarkeit noch nicht bestätigt", "ro": "Disponibilitate neconfirmată încă",
        "uk": "Доступність ще не підтверджено", "fil": "Hindi pa kumpirmado ang availability",
    },
    "availability.unavailable_details": {
        "it": "Questa persona ha indicato di non essere attualmente disponibile per questo servizio.",
        "en": "This person has indicated that they are not currently available for this service.",
        "fr": "Cette personne a indiqué ne pas être actuellement disponible pour ce service.",
        "es": "Esta persona ha indicado que actualmente no está disponible para este servicio.",
        "de": "Diese Person hat angegeben, derzeit für diese Dienstleistung nicht verfügbar zu sein.",
        "ro": "Această persoană a indicat că momentan nu este disponibilă pentru acest serviciu.",
        "uk": "Ця людина зазначила, що зараз недоступна для цієї послуги.",
        "fil": "Sinabi ng taong ito na hindi siya kasalukuyang available para sa serbisyong ito.",
    },
    "availability.card_unconfirmed": {
        "it": "Disponibilità da confermare", "en": "Availability to be confirmed",
        "fr": "Disponibilité à confirmer", "es": "Disponibilidad por confirmar",
        "de": "Verfügbarkeit noch zu bestätigen", "ro": "Disponibilitate de confirmat",
        "uk": "Доступність потребує підтвердження", "fil": "Kailangang kumpirmahin ang availability",
    },
    "availability.card_confirmed_on": {
        "it": "Disponibilità confermata il {date}", "en": "Availability confirmed on {date}",
        "fr": "Disponibilité confirmée le {date}", "es": "Disponibilidad confirmada el {date}",
        "de": "Verfügbarkeit bestätigt am {date}", "ro": "Disponibilitate confirmată la data de {date}",
        "uk": "Доступність підтверджено {date}", "fil": "Kinumpirma ang availability noong {date}",
    },
    "availability.last_confirmed_full": {
        "it": "Ultima conferma: {date}", "en": "Last confirmed: {date}",
        "fr": "Dernière confirmation : {date}", "es": "Última confirmación: {date}",
        "de": "Zuletzt bestätigt: {date}", "ro": "Ultima confirmare: {date}",
        "uk": "Останнє підтвердження: {date}", "fil": "Huling kinumpirma: {date}",
    },
    "availability.edit_this_scope": {
        "it": "Modifica questa disponibilità", "en": "Edit this availability",
        "fr": "Modifier cette disponibilité", "es": "Editar esta disponibilidad",
        "de": "Diese Verfügbarkeit bearbeiten", "ro": "Modifică această disponibilitate",
        "uk": "Редагувати цю доступність", "fil": "I-edit ang availability na ito",
    },
    "availability.configured_scopes": {
        "it": "Disponibilità configurate: {count}", "en": "Configured availability: {count}",
        "fr": "Disponibilités configurées : {count}", "es": "Disponibilidades configuradas: {count}",
        "de": "Konfigurierte Verfügbarkeiten: {count}", "ro": "Disponibilități configurate: {count}",
        "uk": "Налаштовані варіанти доступності: {count}", "fil": "Naka-configure na availability: {count}",
    },
    "availability.view": {
        "it": "Vedi", "en": "View", "fr": "Voir", "es": "Ver",
        "de": "Ansehen", "ro": "Vezi", "uk": "Переглянути", "fil": "Tingnan",
    },
    "availability.add_service_availability": {
        "it": "Aggiungi disponibilità per un servizio",
        "en": "Add availability for a service",
        "fr": "Ajouter une disponibilité pour un service",
        "es": "Añadir disponibilidad para un servicio",
        "de": "Verfügbarkeit für eine Dienstleistung hinzufügen",
        "ro": "Adaugă disponibilitatea pentru un serviciu",
        "uk": "Додати доступність для послуги",
        "fil": "Magdagdag ng availability para sa isang serbisyo",
    },
    "availability.listing_title": {
        "it": "Disponibilità per questo servizio",
        "en": "Availability for this service",
        "fr": "Disponibilité pour ce service",
        "es": "Disponibilidad para este servicio",
        "de": "Verfügbarkeit für diese Dienstleistung",
        "ro": "Disponibilitate pentru acest serviciu",
        "uk": "Доступність для цієї послуги",
        "fil": "Availability para sa serbisyong ito",
    },
    "availability.scope_title": {
        "it": "A quali servizi si applica?",
        "en": "Which services does this apply to?",
        "fr": "À quels services cette disponibilité s’applique-t-elle ?",
        "es": "¿A qué servicios se aplica?",
        "de": "Für welche Dienstleistungen gilt diese Verfügbarkeit?",
        "ro": "Căror servicii li se aplică?",
        "uk": "Для яких послуг діє ця доступність?",
        "fil": "Sa aling mga serbisyo ito naaangkop?",
    },
    "availability.scope_help": {
        "it": "Scegli se questa disponibilità vale per tutti i servizi che offri o per una sola categoria.",
        "en": "Choose whether this availability applies to all the services you offer or to one category.",
        "fr": "Choisissez si cette disponibilité s’applique à tous les services que vous proposez ou à une seule catégorie.",
        "es": "Elige si esta disponibilidad se aplica a todos los servicios que ofreces o a una sola categoría.",
        "de": "Wähle, ob diese Verfügbarkeit für alle von dir angebotenen Dienstleistungen oder nur für eine Kategorie gilt.",
        "ro": "Alege dacă această disponibilitate se aplică tuturor serviciilor pe care le oferi sau unei singure categorii.",
        "uk": "Виберіть, чи ця доступність стосується всіх запропонованих вами послуг або лише однієї категорії.",
        "fil": "Piliin kung ang availability na ito ay para sa lahat ng serbisyong inaalok mo o sa isang kategorya lamang.",
    },
    "availability.scope_general": {
        "it": "Tutti i servizi offerti", "en": "All services offered",
        "fr": "Tous les services proposés", "es": "Todos los servicios ofrecidos",
        "de": "Alle angebotenen Dienstleistungen", "ro": "Toate serviciile oferite",
        "uk": "Усі запропоновані послуги", "fil": "Lahat ng inaalok na serbisyo",
    },
    "availability.scope_category": {
        "it": "Una categoria specifica", "en": "A specific category",
        "fr": "Une catégorie précise", "es": "Una categoría específica",
        "de": "Eine bestimmte Kategorie", "ro": "O categorie specifică",
        "uk": "Окрема категорія", "fil": "Isang partikular na kategorya",
    },
    "availability.choose_category": {
        "it": "Scegli una categoria", "en": "Choose a category",
        "fr": "Choisissez une catégorie", "es": "Elige una categoría",
        "de": "Kategorie auswählen", "ro": "Alege o categorie",
        "uk": "Виберіть категорію", "fil": "Pumili ng kategorya",
    },
    "availability.no_offered_categories": {
        "it": "Non hai ancora categorie di servizi offerti da selezionare.",
        "en": "You do not have any offered service categories to select yet.",
        "fr": "Vous n’avez pas encore de catégorie de services proposés à sélectionner.",
        "es": "Aún no tienes categorías de servicios ofrecidos para seleccionar.",
        "de": "Du hast noch keine angebotene Dienstleistungskategorie zur Auswahl.",
        "ro": "Nu ai încă nicio categorie de servicii oferite pe care să o poți selecta.",
        "uk": "У вас ще немає категорій запропонованих послуг для вибору.",
        "fil": "Wala ka pang kategorya ng inaalok na serbisyo na mapipili.",
    },
    "availability.only_offers_notice": {
        "it": "La disponibilità si può impostare solo per i servizi che offri.",
        "en": "Availability can only be set for services you offer.",
        "fr": "La disponibilité ne peut être définie que pour les services que vous proposez.",
        "es": "La disponibilidad solo se puede configurar para los servicios que ofreces.",
        "de": "Die Verfügbarkeit kann nur für angebotene Dienstleistungen festgelegt werden.",
        "ro": "Disponibilitatea poate fi setată doar pentru serviciile pe care le oferi.",
        "uk": "Доступність можна вказати лише для послуг, які ви пропонуєте.",
        "fil": "Maaari lamang itakda ang availability para sa mga serbisyong inaalok mo.",
    },
    "availability.scope_category_disabled": {
        "it": "Aggiungi prima almeno un servizio offerto nel profilo o in un annuncio.",
        "en": "First add at least one offered service to your profile or a listing.",
        "fr": "Ajoutez d’abord au moins un service proposé à votre profil ou à une annonce.",
        "es": "Primero añade al menos un servicio ofrecido a tu perfil o a un anuncio.",
        "de": "Füge zuerst mindestens eine angebotene Dienstleistung zu deinem Profil oder einer Anzeige hinzu.",
        "ro": "Adaugă mai întâi cel puțin un serviciu oferit în profil sau într-un anunț.",
        "uk": "Спочатку додайте принаймні одну запропоновану послугу до профілю або оголошення.",
        "fil": "Magdagdag muna ng kahit isang inaalok na serbisyo sa profile o listing mo.",
    },
    "availability.public_data_notice": {
        "it": "Giorni, fasce e date saranno visibili pubblicamente. Non inserire informazioni personali.",
        "en": "Days, times and dates will be publicly visible. Do not enter personal information.",
        "fr": "Les jours, créneaux et dates seront visibles publiquement. N’ajoutez aucune information personnelle.",
        "es": "Los días, franjas y fechas serán visibles públicamente. No introduzcas información personal.",
        "de": "Tage, Zeiten und Daten sind öffentlich sichtbar. Gib keine persönlichen Informationen ein.",
        "ro": "Zilele, intervalele și datele vor fi vizibile public. Nu introduce informații personale.",
        "uk": "Дні, час і дати будуть видимі публічно. Не вводьте особисту інформацію.",
        "fil": "Makikita ng publiko ang mga araw, oras, at petsa. Huwag maglagay ng personal na impormasyon.",
    },
    "availability.delete_profile": {
        "it": "Rimuovi disponibilità", "en": "Remove availability", "fr": "Retirer la disponibilité",
        "es": "Quitar disponibilidad", "de": "Verfügbarkeit entfernen", "ro": "Elimină disponibilitatea",
        "uk": "Прибрати доступність", "fil": "Alisin ang availability",
    },
    "availability.delete_profile_confirm": {
        "it": "Vuoi eliminare questa disponibilità?", "en": "Do you want to delete this availability?",
        "fr": "Voulez-vous supprimer cette disponibilité ?", "es": "¿Quieres eliminar esta disponibilidad?",
        "de": "Möchtest du diese Verfügbarkeit löschen?", "ro": "Vrei să ștergi această disponibilitate?",
        "uk": "Ви хочете видалити цю доступність?", "fil": "Gusto mo bang i-delete ang availability na ito?",
    },
    "availability.deleting": {
        "it": "Eliminazione...", "en": "Deleting...", "fr": "Suppression...", "es": "Eliminando...",
        "de": "Wird gelöscht...", "ro": "Se șterge...", "uk": "Видалення...", "fil": "Dine-delete...",
    },
    "availability.deleted": {
        "it": "Disponibilità eliminata.", "en": "Availability deleted.", "fr": "Disponibilité supprimée.",
        "es": "Disponibilidad eliminada.", "de": "Verfügbarkeit gelöscht.", "ro": "Disponibilitate ștearsă.",
        "uk": "Доступність видалено.", "fil": "Na-delete ang availability.",
    },
    "availability.delete_privacy_note": {
        "it": "Saranno eliminate solo le informazioni di disponibilità di questo ambito.",
        "en": "Only the availability information for this scope will be deleted.",
        "fr": "Seules les informations de disponibilité de ce champ seront supprimées.",
        "es": "Solo se eliminará la información de disponibilidad de este ámbito.",
        "de": "Nur die Verfügbarkeitsangaben für diesen Bereich werden gelöscht.",
        "ro": "Vor fi șterse doar informațiile de disponibilitate pentru acest domeniu.",
        "uk": "Буде видалено лише інформацію про доступність для цієї сфери.",
        "fil": "Impormasyon lamang sa availability para sa saklaw na ito ang ide-delete.",
    },
    "availability.delete_profile_category_fallback": {
        "it": "Gli annunci di questa categoria useranno la disponibilità generale, se impostata.",
        "en": "Listings in this category will use your general availability, if set.",
        "fr": "Les annonces de cette catégorie utiliseront votre disponibilité générale, si elle est définie.",
        "es": "Los anuncios de esta categoría usarán tu disponibilidad general, si está configurada.",
        "de": "Anzeigen in dieser Kategorie verwenden deine allgemeine Verfügbarkeit, falls festgelegt.",
        "ro": "Anunțurile din această categorie vor folosi disponibilitatea generală, dacă este setată.",
        "uk": "Оголошення цієї категорії використовуватимуть загальну доступність, якщо її задано.",
        "fil": "Gagamitin ng mga listing sa kategoryang ito ang pangkalahatang availability mo, kung nakatakda.",
    },
    "availability.category.operatori-benessere": {
        "it": "Operatori benessere", "en": "Wellbeing professionals", "fr": "Professionnels du bien-être", "es": "Profesionales del bienestar",
        "de": "Wellness-Fachkräfte", "ro": "Specialiști în wellness", "uk": "Фахівці з добробуту", "fil": "Mga wellbeing professional",
    },
    "availability.category.aiuto-in-casa": {
        "it": "Aiuto in casa", "en": "Home help", "fr": "Aide à domicile", "es": "Ayuda en casa",
        "de": "Haushaltshilfe", "ro": "Ajutor la domiciliu", "uk": "Допомога вдома", "fil": "Tulong sa bahay",
    },
    "availability.category.ripetizioni": {
        "it": "Ripetizioni", "en": "Tutoring", "fr": "Soutien scolaire", "es": "Clases particulares",
        "de": "Nachhilfe", "ro": "Meditații", "uk": "Репетиторство", "fil": "Tutoring",
    },
    "availability.category.babysitter": {
        "it": "Babysitter", "en": "Babysitter", "fr": "Baby-sitter", "es": "Niñera/o",
        "de": "Babysitter", "ro": "Babysitter", "uk": "Бебісітер", "fil": "Babysitter",
    },
    "availability.category.pet-sitter": {
        "it": "Pet-sitter", "en": "Pet sitter", "fr": "Pet-sitter", "es": "Cuidador de mascotas",
        "de": "Tierbetreuung", "ro": "Îngrijitor de animale", "uk": "Догляд за тваринами", "fil": "Pet sitter",
    },
    "availability.category.caregiver": {
        "it": "Caregiver", "en": "Caregiver", "fr": "Auxiliaire de vie", "es": "Cuidador/a",
        "de": "Pflegeperson", "ro": "Îngrijitor", "uk": "Доглядальник", "fil": "Caregiver",
    },
    "availability.category.escursioni-sport": {
        "it": "Sport", "en": "Sports", "fr": "Sport", "es": "Deporte",
        "de": "Sport", "ro": "Sport", "uk": "Спорт", "fil": "Sports",
    },
    "availability.category.biglietti-spettacoli": {
        "it": "Biglietti spettacoli", "en": "Event tickets", "fr": "Billets de spectacles", "es": "Entradas para espectáculos",
        "de": "Veranstaltungstickets", "ro": "Bilete la spectacole", "uk": "Квитки на події", "fil": "Mga ticket sa event",
    },
    "availability.category.libri-scuola": {
        "it": "Libri scuola", "en": "School books", "fr": "Livres scolaires", "es": "Libros escolares",
        "de": "Schulbücher", "ro": "Cărți școlare", "uk": "Шкільні книги", "fil": "Mga school book",
    },
    "availability.category.caffe-parole": {
        "it": "Caffè & parole", "en": "Coffee & conversation", "fr": "Café & conversation", "es": "Café y conversación",
        "de": "Kaffee & Gespräch", "ro": "Cafea și conversație", "uk": "Кава й розмови", "fil": "Kape at kuwentuhan",
    },
    "availability.category.family-kids": {
        "it": "Family & Kids", "en": "Family & Kids", "fr": "Famille & enfants", "es": "Familia y niños",
        "de": "Familie & Kinder", "ro": "Familie și copii", "uk": "Сім’я та діти", "fil": "Pamilya at mga bata",
    },
    "availability.category.eventi-socialita": {
        "it": "Eventi & Socialità", "en": "Events & Social life", "fr": "Événements & vie sociale", "es": "Eventos y vida social",
        "de": "Events & soziales Leben", "ro": "Evenimente și socializare", "uk": "Події та спілкування", "fil": "Mga event at social life",
    },
    "availability.category.spazi-sale": {
        "it": "Spazi & Sale", "en": "Spaces & Venues", "fr": "Espaces & salles", "es": "Espacios y salas",
        "de": "Räume & Säle", "ro": "Spații și săli", "uk": "Простори та зали", "fil": "Mga espasyo at venue",
    },
    "availability.listing_description_placeholder": {
        "it": "Descrivi nel dettaglio cosa offri, la tua esperienza e le informazioni utili.",
        "en": "Describe in detail what you offer, your experience and useful information.",
        "fr": "Décrivez en détail ce que vous proposez, votre expérience et les informations utiles.",
        "es": "Describe en detalle lo que ofreces, tu experiencia y la información útil.",
        "de": "Beschreibe ausführlich dein Angebot, deine Erfahrung und hilfreiche Informationen.",
        "ro": "Descrie în detaliu ce oferi, experiența ta și informațiile utile.",
        "uk": "Докладно опишіть, що ви пропонуєте, свій досвід і корисну інформацію.",
        "fil": "Ilarawan nang detalyado ang inaalok mo, iyong karanasan, at mahahalagang impormasyon.",
    },
    "availability.contact_preferences_title": {
        "it": "Preferenze di contatto", "en": "Contact preferences",
        "fr": "Préférences de contact", "es": "Preferencias de contacto",
        "de": "Kontaktpräferenzen", "ro": "Preferințe de contact",
        "uk": "Налаштування зв’язку", "fil": "Mga kagustuhan sa pakikipag-ugnayan",
    },
    "availability.contact_preferences_subtitle": {
        "it": "Specifica quando e come preferisci essere contattato.",
        "en": "Specify when and how you prefer to be contacted.",
        "fr": "Indiquez quand et comment vous préférez être contacté.",
        "es": "Indica cuándo y cómo prefieres que te contacten.",
        "de": "Gib an, wann und wie du kontaktiert werden möchtest.",
        "ro": "Indică când și cum preferi să fii contactat.",
        "uk": "Вкажіть, коли і як з вами краще зв’язатися.",
        "fil": "Tukuyin kung kailan at paano mo gustong makontak.",
    },
    "availability.contacts_sidebar_description": {
        "it": "Email, telefono, social e preferenze",
        "en": "Email, phone, social profiles and preferences",
        "fr": "E-mail, téléphone, réseaux sociaux et préférences",
        "es": "Correo, teléfono, redes sociales y preferencias",
        "de": "E-Mail, Telefon, soziale Profile und Präferenzen",
        "ro": "E-mail, telefon, rețele sociale și preferințe",
        "uk": "Електронна пошта, телефон, соцмережі та налаштування",
        "fil": "Email, telepono, social profiles, at mga kagustuhan",
    },
    "profile_card.category_sport": {
        "it": "Sport", "en": "Sports", "fr": "Sport",
        "es": "Deporte", "de": "Sport", "ro": "Sport",
        "uk": "Спорт", "fil": "Sports",
    },
}


BASE_LANGUAGE_ORDER = ("it", "en", "fr", "es", "de")
EXTRA_LANGUAGE_ORDER = ("ro", "uk", "fil")
LANGUAGE_ORDER = BASE_LANGUAGE_ORDER + EXTRA_LANGUAGE_ORDER
PATTERN_BASE_LANGUAGE_ORDER = ("en", "fr", "es", "de")


def _load_extra_translation_catalog():
    """Carica le lingue aggiuntive mantenendo compatto il catalogo Python."""
    path = Path(__file__).with_name("extra_translations.json")
    if not path.exists():
        return {}, {}

    payload = json.loads(path.read_text(encoding="utf-8"))
    sources = payload.get("sources", {})
    patterns = payload.get("patterns", {})
    expected = set(EXTRA_LANGUAGE_ORDER)

    for source, variants in sources.items():
        if set(variants) != expected:
            raise ValueError(f"Traduzione aggiuntiva incompleta per {source!r}")

    for pattern, variants in patterns.items():
        if set(variants) != expected:
            raise ValueError(f"Pattern aggiuntivo incompleto per {pattern!r}")

    return sources, patterns


EXTRA_SOURCE_TRANSLATIONS, EXTRA_PATTERN_TRANSLATIONS = (
    _load_extra_translation_catalog()
)

# Revisione manuale delle frasi più visibili e sensibili. Il catalogo completo
# resta generato offline; queste correzioni evitano ambiguità nei comandi
# principali, nella registrazione e negli avvisi legali.
EXTRA_SOURCE_TRANSLATION_OVERRIDES = {
    "Il testo legale ufficiale è quello in italiano.": {
        "ro": "Traducere de curtoazie. În caz de neconcordanțe, prevalează textul oficial în limba italiană.",
        "uk": "Неофіційний переклад. У разі розбіжностей переважну силу має офіційний текст італійською мовою.",
        "fil": "Pagsasalin para sa kaginhawaan. Kung may pagkakaiba, mananaig ang opisyal na tekstong Italyano.",
    },
    "Cambia lingua": {
        "ro": "Schimbă limba",
        "uk": "Змінити мову",
        "fil": "Baguhin ang wika",
    },
    "Chiudi": {"ro": "Închide", "uk": "Закрити", "fil": "Isara"},
    "Accedi": {"ro": "Conectează-te", "uk": "Увійти", "fil": "Mag-sign in"},
    "Registrati": {"ro": "Înregistrează-te", "uk": "Зареєструватися", "fil": "Magrehistro"},
    "Esci": {"ro": "Deconectează-te", "uk": "Вийти", "fil": "Mag-sign out"},
    "Il passaparola di una volta, a portata di mano!": {
        "ro": "Recomandările de altădată, acum la îndemâna ta!",
        "uk": "Сарафанне радіо, як колись, тепер у вас під рукою!",
        "fil": "Ang tradisyonal na rekomendasyon ng komunidad, abot-kamay mo na!",
    },
    "Scegli la tua zona per entrare nella rete locale di persone vicino a te.": {
        "ro": "Alege zona ta pentru a intra în rețeaua locală a persoanelor din apropiere.",
        "uk": "Виберіть свій район, щоб долучитися до місцевої мережі людей поруч із вами.",
        "fil": "Piliin ang iyong lugar para makasali sa lokal na network ng mga taong malapit sa iyo.",
    },
    "Cognome": {"ro": "Nume de familie", "uk": "Прізвище", "fil": "Apelyido"},
    "Email": {"ro": "E-mail", "uk": "Електронна пошта", "fil": "Email"},
    "Password": {"ro": "Parolă", "uk": "Пароль", "fil": "Password"},
    "Conferma password": {
        "ro": "Confirmă parola",
        "uk": "Підтвердіть пароль",
        "fil": "Kumpirmahin ang password",
    },
    "Informativa sulla Privacy": {
        "ro": "Politica de confidențialitate",
        "uk": "Політика конфіденційності",
        "fil": "Patakaran sa Privacy",
    },
    "Cookie Policy": {
        "ro": "Politica privind modulele cookie",
        "uk": "Політика файлів cookie",
        "fil": "Patakaran sa Cookie",
    },
    "Termini e Condizioni": {
        "ro": "Termeni și condiții",
        "uk": "Умови використання",
        "fil": "Mga Tuntunin at Kundisyon",
    },
    "Mostra password": {
        "ro": "Afișează parola",
        "uk": "Показати пароль",
        "fil": "Ipakita ang password",
    },
    "Nascondi password": {
        "ro": "Ascunde parola",
        "uk": "Приховати пароль",
        "fil": "Itago ang password",
    },
    "Le password non coincidono.": {
        "ro": "Parolele nu coincid.",
        "uk": "Паролі не збігаються.",
        "fil": "Hindi magkatugma ang mga password.",
    },
    "Caricamento stato visibilità…": {
        "ro": "Se încarcă starea vizibilității…",
        "uk": "Завантаження стану видимості…",
        "fil": "Nilo-load ang status ng visibility…",
    },
    "Caricamento foto... Attendi senza chiudere la pagina.": {
        "ro": "Se încarcă fotografia... Așteaptă fără să închizi pagina.",
        "uk": "Завантаження фото... Зачекайте, не закриваючи сторінку.",
        "fil": "Ina-upload ang larawan... Maghintay nang hindi isinasara ang pahina.",
    },
    "Elimina una foto prima di aggiungerne una nuova.": {
        "ro": "Șterge o fotografie înainte de a adăuga una nouă.",
        "uk": "Видаліть фото, перш ніж додати нове.",
        "fil": "Mag-delete muna ng larawan bago magdagdag ng bago.",
    },
}

for source, variants in EXTRA_SOURCE_TRANSLATION_OVERRIDES.items():
    EXTRA_SOURCE_TRANSLATIONS.setdefault(source, {}).update(variants)


def _build_source_translations():
    """Crea il catalogo basato sui testi italiani già presenti nei template."""
    catalog = {}

    for variants in TRANSLATIONS.values():
        italian = variants.get("it")
        if italian:
            catalog[italian] = {
                code: variants.get(code) or variants.get("en") or italian
                for code in BASE_LANGUAGE_ORDER
            }
            catalog[italian].update(EXTRA_SOURCE_TRANSLATIONS.get(italian, {}))
            catalog[italian].update({
                code: variants[code]
                for code in EXTRA_LANGUAGE_ORDER
                if variants.get(code)
            })

    for row in PHRASE_ROWS:
        if len(row) != len(BASE_LANGUAGE_ORDER):
            raise ValueError(f"Riga traduzione non valida: {row!r}")
        italian = row[0]
        catalog[italian] = dict(zip(BASE_LANGUAGE_ORDER, row))
        catalog[italian].update(EXTRA_SOURCE_TRANSLATIONS.get(italian, {}))

    return catalog


SOURCE_TRANSLATIONS = _build_source_translations()


def _load_legal_source_translations():
    """Carica le traduzioni legali complete senza appesantire il catalogo JS."""
    path = Path(__file__).with_name("legal_translations.json")
    if not path.exists():
        return {}

    catalog = json.loads(path.read_text(encoding="utf-8"))
    expected = set(BASE_LANGUAGE_ORDER)

    for source, variants in catalog.items():
        if set(variants) != expected:
            raise ValueError(f"Traduzione legale incompleta per {source!r}")
        variants.update(EXTRA_SOURCE_TRANSLATIONS.get(source, {}))
        if EXTRA_SOURCE_TRANSLATIONS and set(variants) != set(LANGUAGE_ORDER):
            raise ValueError(f"Traduzione legale aggiuntiva incompleta per {source!r}")

    return catalog


LEGAL_SOURCE_TRANSLATIONS = _load_legal_source_translations()


PATTERN_TRANSLATIONS = []
for row in PATTERN_ROWS:
    variants = dict(zip(PATTERN_BASE_LANGUAGE_ORDER, row[1:]))
    variants.update(EXTRA_PATTERN_TRANSLATIONS.get(row[0], {}))
    PATTERN_TRANSLATIONS.append((re.compile(row[0], re.I), variants))


_SPACE_RE = re.compile(r"\s+")
_LEADING_SYMBOLS_RE = re.compile(r"^([^0-9A-Za-zÀ-ÖØ-öø-ÿ@]+)(.+)$", re.S)
_TRAILING_PUNCTUATION_RE = re.compile(r"^(.+?)(\s*[:;,.!?…]+)$", re.S)
_TRAILING_SYMBOLS_RE = re.compile(r"^(.+?)(\s*[^0-9A-Za-zÀ-ÖØ-öø-ÿ@\s]+)$", re.S)


def _normalize_source_text(value):
    return _SPACE_RE.sub(" ", html.unescape(str(value or ""))).strip()


def _translate_source_core(source, language):
    variants = SOURCE_TRANSLATIONS.get(source) or LEGAL_SOURCE_TRANSLATIONS.get(source)
    if variants:
        return variants.get(language) or variants.get("en") or source

    for pattern, pattern_variants in PATTERN_TRANSLATIONS:
        match = pattern.fullmatch(source)
        if not match:
            continue
        template = pattern_variants.get(language) or pattern_variants.get("en")
        try:
            translated_groups = tuple(
                _translate_source_core(group, language)
                for group in match.groups()
            )
            return template.format(*translated_groups)
        except (IndexError, KeyError, ValueError):
            return source

    leading = _LEADING_SYMBOLS_RE.match(source)
    if leading:
        prefix, core = leading.groups()
        translated = _translate_source_core(core.strip(), language)
        if translated != core.strip():
            return f"{prefix}{translated}"

    trailing = _TRAILING_PUNCTUATION_RE.match(source)
    if trailing:
        core, suffix = trailing.groups()
        translated = _translate_source_core(core.strip(), language)
        if translated != core.strip():
            return f"{translated}{suffix}"

    trailing_symbols = _TRAILING_SYMBOLS_RE.match(source)
    if trailing_symbols:
        core, suffix = trailing_symbols.groups()
        translated = _translate_source_core(core.strip(), language)
        if translated != core.strip():
            return f"{translated}{suffix}"

    return source


def translate_source(value, language="it"):
    """Traduce un testo UI italiano completo preservando gli spazi esterni."""
    language = normalize_language(language)
    if language == "it" or value is None:
        return value

    original = str(value)
    normalized = _normalize_source_text(original)
    if not normalized:
        return original

    translated = _translate_source_core(normalized, language)
    if translated == normalized:
        return original

    leading = original[: len(original) - len(original.lstrip())]
    trailing = original[len(original.rstrip()):]
    return f"{leading}{translated}{trailing}"


_HTML_TEXT_RE = re.compile(r"(?<=>)([^<>]+)(?=<)")
_TRANSLATABLE_ATTR_RE = re.compile(
    # Non tradurre mai `value`: nei form contiene spesso codici applicativi
    # (per esempio "offro", "cerco" o gli slug delle categorie).
    r"(?P<prefix>\b(?:placeholder|title|aria-label|data-label|alt)\s*=\s*)"
    r"(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
    re.I | re.S,
)
_SCRIPT_BLOCK_RE = re.compile(r"(<script\b[^>]*>)(.*?)(</script>)", re.I | re.S)
_NO_TRANSLATE_BLOCK_RE = re.compile(
    r"(<(?P<tag>[a-z][\w:-]*)\b"
    r"(?=[^>]*\bdata-no-translate(?:\s|=|>))[^>]*>"
    r".*?</(?P=tag)\s*>)",
    re.I | re.S,
)


def localize_html_document(document, language="it"):
    """Traduce testo statico e attributi accessibili senza toccare la logica JS."""
    language = normalize_language(language)
    if language == "it" or not document:
        return document

    protected_blocks = []

    def protect_no_translate(match):
        index = len(protected_blocks)
        protected_blocks.append(match.group(1))
        return f'<template data-mlc-protected-block="{index}"></template>'

    localized = _NO_TRANSLATE_BLOCK_RE.sub(protect_no_translate, document)

    scripts = []

    def protect_script(match):
        index = len(scripts)
        scripts.append(match.groups())
        return f"<template data-mlc-script-placeholder=\"{index}\"></template>"

    localized = _SCRIPT_BLOCK_RE.sub(protect_script, localized)
    def replace_text(match):
        original = match.group(1)
        translated = translate_source(original, language)
        if translated == original:
            return original
        return html.escape(str(translated), quote=False)

    localized = _HTML_TEXT_RE.sub(replace_text, localized)

    def replace_attribute(match):
        translated = translate_source(match.group("value"), language)
        escaped = html.escape(str(translated), quote=True)
        return (
            f"{match.group('prefix')}{match.group('quote')}"
            f"{escaped}{match.group('quote')}"
        )

    localized = _TRANSLATABLE_ATTR_RE.sub(replace_attribute, localized)

    for index, (opening, script, closing) in enumerate(scripts):
        placeholder = f'<template data-mlc-script-placeholder="{index}"></template>'
        localized = localized.replace(
            placeholder,
            f"{opening}{script}{closing}",
            1,
        )

    for index, block in enumerate(protected_blocks):
        placeholder = f'<template data-mlc-protected-block="{index}"></template>'
        localized = localized.replace(placeholder, block, 1)

    return localized


def frontend_source_catalog(language="it"):
    """Catalogo compatto per contenuti aggiunti dinamicamente nel browser."""
    language = normalize_language(language)
    if language == "it":
        return {}
    return {
        source: variants.get(language) or variants.get("en") or source
        for source, variants in SOURCE_TRANSLATIONS.items()
        if (variants.get(language) or source) != source
    }


def frontend_source_catalog_b64(language="it"):
    payload = json.dumps(
        frontend_source_catalog(language),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def frontend_pattern_catalog(language="it"):
    language = normalize_language(language)
    if language == "it":
        return []
    return [
        {"source": pattern.pattern, "target": variants[language]}
        for pattern, variants in PATTERN_TRANSLATIONS
        if variants.get(language)
    ]


def frontend_pattern_catalog_b64(language="it"):
    payload = json.dumps(
        frontend_pattern_catalog(language),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def normalize_language(value):
    code = str(value or "").strip().lower().replace("_", "-").split("-", 1)[0]
    return code if code in SUPPORTED_LANGUAGES else "it"


def translate(key, language="it", **values):
    language = normalize_language(language)
    variants = TRANSLATIONS.get(key, {})
    italian = variants.get("it")
    text = variants.get(language)
    if not text and italian:
        text = EXTRA_SOURCE_TRANSLATIONS.get(italian, {}).get(language)
    text = text or italian or key

    if values:
        try:
            return text.format(**values)
        except (KeyError, ValueError):
            return text

    return text
