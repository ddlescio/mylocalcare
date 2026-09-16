"""Traduzioni dell'interfaccia MyLocalCare, senza contenuti scritti dagli utenti."""

import base64
import html
import json
import re

from i18n_catalog import PATTERN_ROWS, PHRASE_ROWS

SUPPORTED_LANGUAGES = {
    "it": {"label": "Italiano", "flag": "🇮🇹", "short": "IT"},
    "en": {"label": "English", "flag": "🇬🇧", "short": "EN"},
    "fr": {"label": "Français", "flag": "🇫🇷", "short": "FR"},
    "es": {"label": "Español", "flag": "🇪🇸", "short": "ES"},
    "de": {"label": "Deutsch", "flag": "🇩🇪", "short": "DE"},
}


TRANSLATIONS = {
    "legal.official_language_notice": {
        "it": "Il testo legale ufficiale è disponibile in italiano.",
        "en": "The official legal text is provided in Italian.",
        "fr": "Le texte juridique officiel est fourni en italien.",
        "es": "El texto legal oficial se proporciona en italiano.",
        "de": "Der verbindliche Rechtstext ist auf Italienisch verfügbar.",
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
    "search.my_interests": {
        "it": "I miei interessi", "en": "My interests", "fr": "Mes favoris",
        "es": "Mis intereses", "de": "Meine Interessen",
    },
}


LANGUAGE_ORDER = ("it", "en", "fr", "es", "de")
PATTERN_LANGUAGE_ORDER = ("en", "fr", "es", "de")


def _build_source_translations():
    """Crea il catalogo basato sui testi italiani già presenti nei template."""
    catalog = {}

    for variants in TRANSLATIONS.values():
        italian = variants.get("it")
        if italian:
            catalog[italian] = {
                code: variants.get(code) or variants.get("en") or italian
                for code in LANGUAGE_ORDER
            }

    for row in PHRASE_ROWS:
        if len(row) != len(LANGUAGE_ORDER):
            raise ValueError(f"Riga traduzione non valida: {row!r}")
        italian = row[0]
        catalog[italian] = dict(zip(LANGUAGE_ORDER, row))

    return catalog


SOURCE_TRANSLATIONS = _build_source_translations()


PATTERN_TRANSLATIONS = [
    (
        re.compile(row[0], re.I),
        dict(zip(PATTERN_LANGUAGE_ORDER, row[1:])),
    )
    for row in PATTERN_ROWS
]


_SPACE_RE = re.compile(r"\s+")
_LEADING_SYMBOLS_RE = re.compile(r"^([^0-9A-Za-zÀ-ÖØ-öø-ÿ@]+)(.+)$", re.S)
_TRAILING_PUNCTUATION_RE = re.compile(r"^(.+?)(\s*[:;,.!?…]+)$", re.S)
_TRAILING_SYMBOLS_RE = re.compile(r"^(.+?)(\s*[^0-9A-Za-zÀ-ÖØ-öø-ÿ@\s]+)$", re.S)


def _normalize_source_text(value):
    return _SPACE_RE.sub(" ", html.unescape(str(value or ""))).strip()


def _translate_source_core(source, language):
    variants = SOURCE_TRANSLATIONS.get(source)
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


def localize_html_document(document, language="it"):
    """Traduce testo statico e attributi accessibili senza toccare la logica JS."""
    language = normalize_language(language)
    if language == "it" or not document:
        return document

    scripts = []

    def protect_script(match):
        index = len(scripts)
        scripts.append(match.groups())
        return f"<template data-mlc-script-placeholder=\"{index}\"></template>"

    localized = _SCRIPT_BLOCK_RE.sub(protect_script, document)
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
        {
            "source": row[0],
            "target": row[LANGUAGE_ORDER.index(language)],
        }
        for row in PATTERN_ROWS
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
    text = variants.get(language) or variants.get("it") or key

    if values:
        try:
            return text.format(**values)
        except (KeyError, ValueError):
            return text

    return text
