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


TRANSLATIONS = {
    "legal.official_language_notice": {
        "it": "Il testo legale ufficiale è quello in italiano.",
        "en": "Courtesy translation. In case of discrepancies, the official Italian text prevails.",
        "fr": "Traduction de courtoisie. En cas de divergence, le texte officiel italien prévaut.",
        "es": "Traducción de cortesía. En caso de discrepancia, prevalece el texto oficial en italiano.",
        "de": "Unverbindliche Übersetzung. Bei Abweichungen ist der offizielle italienische Text maßgeblich.",
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
