import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    ROOT / "migrations" / "20261002_disponibilita_solo_annunci_offro.sql"
)


class DisponibilitaOrphanMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MIGRATION_PATH.read_text(encoding="utf-8")
        without_comments = re.sub(r"--[^\n]*", "", cls.source)
        cls.sql = re.sub(r"\s+", " ", without_comments.lower()).strip()

    def test_bonifica_e_transazionale_e_copre_tutte_le_tabelle(self):
        self.assertRegex(self.sql, r"^begin\s*;")
        self.assertRegex(self.sql, r"commit\s*;")

        for table in (
            "annunci_disponibilita_eventi",
            "annunci_disponibilita_ciclo",
            "disponibilita_profili_categoria",
            "disponibilita_intervalli",
            "disponibilita_settimanale",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
            "disponibilita_profili",
            "disponibilita_promemoria_eventi",
        ):
            self.assertIn(f"delete from {table}", self.sql, table)

        for state in (
            "'in_attesa'",
            "'approvato'",
            "'archiviato_disponibilita'",
        ):
            self.assertIn(state, self.sql)
        self.assertIn("tipo_annuncio = 'offro'", self.sql)

    def test_scope_e_outbox_sono_protetti_dalle_scritture_concorrenti(self):
        setup = self.sql.split("create temp table", 1)[0]
        self.assertIn("lock table annunci in share mode", setup)
        self.assertIn(
            "lock table disponibilita_promemoria_eventi "
            "in access exclusive mode",
            setup,
        )

        instructions = self.source.lower()
        self.assertIn("cron", instructions)
        self.assertIn("worker", instructions)
        self.assertTrue(
            any(word in instructions for word in ("sospes", "fermat", "pausa")),
            "La migrazione deve dire esplicitamente di sospendere il worker "
            "dei promemoria prima dell'esecuzione.",
        )

    def test_categoria_annuncio_usa_una_normalizzazione_compatibile_con_slug(
        self,
    ):
        # Le righe legacy possono contenere etichette (per esempio
        # "Aiuto in casa" o "Caffè & parole"), mentre il profilo conserva
        # sempre lo slug. Il solo LOWER cancellerebbe profili ancora validi.
        self.assertNotIn(
            "lower(annuncio.categoria) = lower(profilo.categoria_slug)",
            self.sql,
        )
        has_slug_expression = (
            "regexp_replace" in self.sql and "translate" in self.sql
        )
        has_explicit_mapping = all(
            value in self.sql
            for value in (
                "aiuto-in-casa",
                "escursioni-sport",
                "caffe-parole",
                "eventi-socialita",
            )
        ) and "values" in self.sql
        self.assertTrue(
            has_slug_expression or has_explicit_mapping,
            "La categoria dell'annuncio deve essere convertita nello stesso "
            "slug usato da disponibilita_profili_categoria.",
        )
        for legacy, canonical in (
            ("petsitter", "pet-sitter"),
            ("sport", "escursioni-sport"),
        ):
            self.assertRegex(
                self.sql,
                rf"'{legacy}'.{{0,120}}'{canonical}'",
                f"L'alias `{legacy}` deve conservare il profilo canonico "
                f"`{canonical}`.",
            )

    def test_profilo_generale_dipende_da_qualsiasi_offro_valido(self):
        user_scope = re.search(
            r"create temp table _utenti_con_offerte_attive\b(?P<body>.*?)"
            r"create temp table _disponibilita_offerte_attive\b",
            self.sql,
        )
        self.assertIsNotNone(user_scope)
        scope_body = user_scope.group("body")
        self.assertIn("tipo_annuncio = 'offro'", scope_body)
        for state in (
            "'in_attesa'",
            "'approvato'",
            "'archiviato_disponibilita'",
        ):
            self.assertIn(state, scope_body)
        self.assertNotIn("categoria_slug in", scope_body)

        for table in (
            "disponibilita_intervalli",
            "disponibilita_settimanale",
            "disponibilita_date_speciali",
            "disponibilita_assenze",
            "disponibilita_profili",
        ):
            delete = re.search(
                rf"delete from {table}\b(?P<body>.*?);",
                self.sql,
            )
            self.assertIsNotNone(delete, table)
            self.assertIn(
                "_utenti_con_offerte_attive",
                delete.group("body"),
                table,
            )

    def test_outbox_elimina_solo_eventi_incompleti_di_utenti_senza_offerte(
        self,
    ):
        match = re.search(
            r"delete from disponibilita_promemoria_eventi\b(?P<body>.*?);",
            self.sql,
        )
        self.assertIsNotNone(match)
        body = match.group("body")

        for delivered_at in (
            "notifica_interna_at is null",
            "push_inviata_at is null",
            "email_inviata_at is null",
        ):
            self.assertIn(delivered_at, body)
        self.assertIn("not exists", body)
        self.assertTrue(
            "tipo_annuncio = 'offro'" in body
            or "_utenti_con_offerte_attive" in body,
            "Il reminder va confrontato con lo scope di tutti gli utenti "
            "che conservano almeno un OFFRO valido.",
        )

        # Un evento senza categoria resta aggregato e dipende da qualunque
        # OFFRO. Se il link identifica invece una categoria, quella specifica
        # offerta deve ancora esistere: mantenere un'altra categoria non basta.
        self.assertIn("evento.link", body)
        self.assertIn("categoria=", body)
        self.assertIn("_disponibilita_offerte_attive", body)
        self.assertIn("split_part", body)


if __name__ == "__main__":
    unittest.main()
