//! WS3-6 — Russian and Uzbek display labels for entity classes.
//!
//! # Why a table and not a translation layer
//!
//! The PRD requires the leak report in RU/UZ. This repo has NO i18n
//! infrastructure to follow: `secureprompt-web` has no locale directory, no
//! `next-intl` / `react-i18next` / `formatjs` dependency, and nothing in the
//! Rust or Python services reads `Accept-Language`. Inventing a framework here
//! would be a bigger decision than this task, made in the wrong place.
//!
//! So the report keeps its STRUCTURE language-neutral — stable machine keys
//! (`PERSON`, `EMAIL_ADDRESS`) and integers — and carries the human labels
//! beside it as DATA. Consequences, all deliberate:
//!
//! * A caller that wants a third locale adds a column to this table. No
//!   handler, no query and no response shape changes.
//! * A caller that wants none ignores `labels`; the numbers are still keyed by
//!   something stable.
//! * When the product does grow an i18n layer, this table is the thing it
//!   imports, not something it has to reverse-engineer out of formatting code.
//!
//! The response ships BOTH locales at once rather than negotiating one,
//! because a pilot report is read by more than one person and the payload is
//! a few hundred bytes.
//!
//! # Uzbek script
//!
//! `uz` here is Uzbek in the LATIN alphabet, which is the official script.
//! Uzbek Cyrillic (`uz-Cyrl`) is genuinely still in use in Uzbek banking
//! documents — this project's own NER work evaluates `uz-latn` and `uz-cyrl`
//! separately — and it is deliberately NOT shipped rather than machine-
//! transliterated: a transliteration nobody has read is a worse artifact than
//! an absent locale in a document a compliance officer signs. Adding it is one
//! more column in `LABELS`.

/// `(class, ru, uz-Latn)` for every class in
/// `analytics::detection_counts::CANONICAL_CLASSES`, plus the `other` bucket.
///
/// `tests::every_canonical_class_has_labels` derives the expected key set from
/// `CANONICAL_CLASSES` itself, so a class added there without a label reddens
/// rather than silently rendering as a bare machine key in a bank's report.
pub const LABELS: &[(&str, &str, &str)] = &[
    // ── the bucket ───────────────────────────────────────────────────────
    (
        "other",
        "Прочий класс (не распознан шлюзом)",
        "Boshqa turkum (shlyuz tanimadi)",
    ),
    // ── credentials and secrets ──────────────────────────────────────────
    (
        "ANTHROPIC_API_KEY",
        "Ключ API Anthropic",
        "Anthropic API kaliti",
    ),
    ("API_TOKEN_GENERIC", "Токен API", "API tokeni"),
    ("AWS_ACCESS_KEY", "Ключ доступа AWS", "AWS kirish kaliti"),
    (
        "AZURE_STORAGE_CONNECTION_STRING",
        "Строка подключения Azure Storage",
        "Azure Storage ulanish satri",
    ),
    ("AZURE_KEY", "Ключ Azure", "Azure kaliti"),
    (
        "BASIC_AUTH_HEADER",
        "Заголовок Basic-авторизации",
        "Basic avtorizatsiya sarlavhasi",
    ),
    ("BEARER_TOKEN", "Токен Bearer", "Bearer tokeni"),
    ("GCP_KEY", "Ключ Google Cloud", "Google Cloud kaliti"),
    (
        "GCP_SERVICE_ACCOUNT_EMAIL",
        "Служебный аккаунт Google Cloud",
        "Google Cloud xizmat hisobi",
    ),
    (
        "GITHUB_FINE_GRAINED_PAT",
        "Токен GitHub (детальные права)",
        "GitHub tokeni (batafsil huquqlar)",
    ),
    (
        "GITHUB_OAUTH_TOKEN",
        "Токен OAuth GitHub",
        "GitHub OAuth tokeni",
    ),
    ("GITHUB_PAT", "Личный токен GitHub", "GitHub shaxsiy tokeni"),
    (
        "GITHUB_REFRESH_TOKEN",
        "Токен обновления GitHub",
        "GitHub yangilash tokeni",
    ),
    ("GOOGLE_API_KEY", "Ключ API Google", "Google API kaliti"),
    ("JWT", "Веб-токен JWT", "JWT veb-tokeni"),
    (
        "MONGODB_URI",
        "Строка подключения MongoDB",
        "MongoDB ulanish satri",
    ),
    (
        "OAUTH_CLIENT_SECRET",
        "Секрет клиента OAuth",
        "OAuth mijoz maxfiy kaliti",
    ),
    ("OPENAI_API_KEY", "Ключ API OpenAI", "OpenAI API kaliti"),
    (
        "OPENSSH_PRIVATE_KEY",
        "Закрытый ключ OpenSSH",
        "OpenSSH yopiq kaliti",
    ),
    ("PASSWORD_ASSIGNMENT", "Пароль в тексте", "Matndagi parol"),
    (
        "POSTGRESQL_URI",
        "Строка подключения PostgreSQL",
        "PostgreSQL ulanish satri",
    ),
    (
        "PRIVATE_KEY_PEM",
        "Закрытый ключ (PEM)",
        "Yopiq kalit (PEM)",
    ),
    ("RSA_PRIVATE_KEY", "Закрытый ключ RSA", "RSA yopiq kaliti"),
    (
        "SLACK_APP_TOKEN",
        "Токен приложения Slack",
        "Slack ilova tokeni",
    ),
    ("SLACK_BOT_TOKEN", "Токен бота Slack", "Slack bot tokeni"),
    (
        "SLACK_USER_TOKEN",
        "Пользовательский токен Slack",
        "Slack foydalanuvchi tokeni",
    ),
    (
        "STRIPE_PUBLISHABLE_KEY",
        "Публичный ключ Stripe",
        "Stripe ochiq kaliti",
    ),
    (
        "STRIPE_SECRET_KEY",
        "Секретный ключ Stripe",
        "Stripe maxfiy kaliti",
    ),
    ("WEBHOOK_URL", "URL веб-хука", "Veb-huk manzili"),
    // ── people and contact details ───────────────────────────────────────
    (
        "PERSON",
        "Физическое лицо (ФИО)",
        "Jismoniy shaxs (F.I.Sh.)",
    ),
    ("USERNAME", "Имя пользователя", "Foydalanuvchi nomi"),
    (
        "EMAIL_ADDRESS",
        "Адрес электронной почты",
        "Elektron pochta manzili",
    ),
    ("PHONE_NUMBER", "Номер телефона", "Telefon raqami"),
    ("ADDRESS", "Адрес", "Manzil"),
    ("POSTAL_CODE", "Почтовый индекс", "Pochta indeksi"),
    ("LOCATION", "Местоположение", "Joylashuv"),
    ("GPE", "Географический объект", "Geografik obyekt"),
    ("ORGANIZATION", "Организация", "Tashkilot"),
    ("IP_ADDRESS", "IP-адрес", "IP manzil"),
    ("DATE_TIME", "Дата или время", "Sana yoki vaqt"),
    ("DATE_OF_BIRTH", "Дата рождения", "Tug'ilgan sana"),
    ("BLOOD_TYPE", "Группа крови", "Qon guruhi"),
    // ── national and identity documents ──────────────────────────────────
    (
        "PINFL",
        "ПИНФЛ (персональный идентификационный номер)",
        "JSHSHIR (jismoniy shaxsning shaxsiy identifikatsiya raqami)",
    ),
    (
        "STIR",
        "ИНН (идентификационный номер налогоплательщика)",
        "STIR (soliq to'lovchining identifikatsiya raqami)",
    ),
    ("PASSPORT_NUMBER", "Номер паспорта", "Pasport raqami"),
    (
        "PASSPORT_EXPIRATION_DATE",
        "Срок действия паспорта",
        "Pasport amal qilish muddati",
    ),
    (
        "IDENTITY_CARD_NUMBER",
        "Номер удостоверения личности",
        "Shaxsni tasdiqlovchi hujjat raqami",
    ),
    (
        "BIRTH_CERTIFICATE_NUMBER",
        "Номер свидетельства о рождении",
        "Tug'ilganlik guvohnomasi raqami",
    ),
    (
        "DRIVERS_LICENSE_NUMBER",
        "Номер водительского удостоверения",
        "Haydovchilik guvohnomasi raqami",
    ),
    (
        "US_DRIVER_LICENSE",
        "Водительское удостоверение (США)",
        "Haydovchilik guvohnomasi (AQSh)",
    ),
    ("VISA_NUMBER", "Номер визы", "Viza raqami"),
    (
        "STUDENT_ID_NUMBER",
        "Номер студенческого билета",
        "Talaba bileti raqami",
    ),
    ("SERIAL_NUMBER", "Серийный номер", "Seriya raqami"),
    (
        "REGISTRATION_NUMBER",
        "Регистрационный номер",
        "Ro'yxatga olish raqami",
    ),
    (
        "SSN",
        "Номер социального страхования",
        "Ijtimoiy sug'urta raqami",
    ),
    (
        "SOCIAL_SECURITY_NUMBER",
        "Номер социального страхования",
        "Ijtimoiy sug'urta raqami",
    ),
    (
        "US_SSN",
        "Номер социального страхования (США)",
        "Ijtimoiy sug'urta raqami (AQSh)",
    ),
    ("CNPJ", "CNPJ (Бразилия)", "CNPJ (Braziliya)"),
    ("CPF", "CPF (Бразилия)", "CPF (Braziliya)"),
    (
        "TAX_IDENTIFICATION_NUMBER",
        "Идентификационный номер налогоплательщика",
        "Soliq to'lovchi identifikatsiya raqami",
    ),
    // ── banking and payment ──────────────────────────────────────────────
    ("MFO", "МФО (код банка)", "MFO (bank kodi)"),
    ("UZCARD", "Карта Uzcard", "Uzcard kartasi"),
    ("HUMO", "Карта Humo", "Humo kartasi"),
    (
        "CREDIT_CARD",
        "Номер банковской карты",
        "Bank kartasi raqami",
    ),
    (
        "CREDIT_CARD_NUMBER",
        "Номер банковской карты",
        "Bank kartasi raqami",
    ),
    (
        "CREDIT_CARD_BRAND",
        "Платёжная система карты",
        "Karta to'lov tizimi",
    ),
    (
        "CREDIT_CARD_EXPIRATION_DATE",
        "Срок действия карты",
        "Karta amal qilish muddati",
    ),
    ("CVV", "Код CVV/CVC", "CVV/CVC kodi"),
    (
        "IBAN",
        "Международный номер банковского счёта (IBAN)",
        "Xalqaro bank hisob raqami (IBAN)",
    ),
    (
        "IBAN_CODE",
        "Международный номер банковского счёта (IBAN)",
        "Xalqaro bank hisob raqami (IBAN)",
    ),
    (
        "BANK_ACCOUNT_NUMBER",
        "Номер банковского счёта",
        "Bank hisob raqami",
    ),
    (
        "CREDIT_AGREEMENT_ID",
        "Номер кредитного договора",
        "Kredit shartnomasi raqami",
    ),
    ("LOAN_AMOUNT", "Сумма кредита", "Kredit summasi"),
    ("SALARY", "Заработная плата", "Ish haqi"),
    (
        "TRANSACTION_NUMBER",
        "Номер транзакции",
        "Tranzaksiya raqami",
    ),
    // ── medical and insurance ────────────────────────────────────────────
    (
        "MEDICAL_CONDITION",
        "Диагноз или состояние",
        "Tashxis yoki holat",
    ),
    ("MEDICATION", "Лекарственный препарат", "Dori vositasi"),
    (
        "MEDICAL_LICENSE",
        "Номер медицинской лицензии",
        "Tibbiy litsenziya raqami",
    ),
    (
        "INSURANCE_COMPANY",
        "Страховая компания",
        "Sug'urta kompaniyasi",
    ),
    (
        "INSURANCE_NUMBER",
        "Номер страхового полиса",
        "Sug'urta polisi raqami",
    ),
    (
        "HEALTH_INSURANCE_NUMBER",
        "Номер медицинского страхования",
        "Tibbiy sug'urta raqami",
    ),
    (
        "NATIONAL_HEALTH_INSURANCE_NUMBER",
        "Номер национального медицинского страхования",
        "Milliy tibbiy sug'urta raqami",
    ),
    // ── travel and vehicles ──────────────────────────────────────────────
    ("FLIGHT_NUMBER", "Номер рейса", "Reys raqami"),
    ("RESERVATION_NUMBER", "Номер бронирования", "Bron raqami"),
    (
        "TRAIN_TICKET_NUMBER",
        "Номер железнодорожного билета",
        "Temir yo'l chiptasi raqami",
    ),
    (
        "LICENSE_PLATE_NUMBER",
        "Государственный номер автомобиля",
        "Avtomobil davlat raqami",
    ),
    (
        "VEHICLE_REGISTRATION_NUMBER",
        "Регистрационный номер транспортного средства",
        "Transport vositasi ro'yxat raqami",
    ),
];

/// The Russian and Uzbek-Latin labels for `class`, or `None` when the class
/// has no entry.
///
/// `None` rather than a fallback to the machine key: the caller decides how to
/// present an unlabelled class, and a silent fallback would make the missing
/// label invisible to `every_canonical_class_has_labels`.
#[must_use]
pub fn lookup(class: &str) -> Option<(&'static str, &'static str)> {
    LABELS
        .iter()
        .find(|(key, _, _)| *key == class)
        .map(|(_, ru, uz)| (*ru, *uz))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::detection_counts::{CANONICAL_CLASSES, OTHER};
    use std::collections::BTreeSet;

    /// Every class the counts table can hold must be labelled, or a bank's
    /// report renders `NATIONAL_HEALTH_INSURANCE_NUMBER` at a compliance
    /// review.
    ///
    /// The expected set is CANONICAL_CLASSES itself, so this cannot drift.
    #[test]
    fn every_canonical_class_has_labels() {
        assert!(
            CANONICAL_CLASSES.len() > 50,
            "premise failed: CANONICAL_CLASSES has only {} entries, so this \
             test is checking almost nothing",
            CANONICAL_CLASSES.len()
        );
        let missing: Vec<&str> = CANONICAL_CLASSES
            .iter()
            .chain(std::iter::once(&OTHER))
            .filter(|c| lookup(c).is_none())
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "these classes can appear in a leak report and have no RU/UZ \
             label: {missing:?}"
        );
    }

    /// The reverse direction: a label for a class that can never appear is
    /// dead weight that will rot.
    #[test]
    fn no_label_exists_for_a_class_that_cannot_appear() {
        let known: BTreeSet<&str> = CANONICAL_CLASSES
            .iter()
            .copied()
            .chain(std::iter::once(OTHER))
            .collect();
        let orphans: Vec<&str> = LABELS
            .iter()
            .map(|(k, _, _)| *k)
            .filter(|k| !known.contains(k))
            .collect();
        assert!(
            orphans.is_empty(),
            "labelled classes that `detection_counts` can never emit: {orphans:?}"
        );
    }

    /// A locale filled by copying the other is not a translation, and the
    /// report test that compares `ru` to `uz` for one class would not catch it
    /// across the whole table.
    #[test]
    fn the_two_locales_are_not_copies_of_each_other() {
        let identical: Vec<&str> = LABELS
            .iter()
            .filter(|(_, ru, uz)| ru == uz)
            .map(|(k, _, _)| *k)
            .collect();
        assert!(
            identical.is_empty(),
            "these classes have identical RU and UZ labels, so one column was \
             pasted from the other: {identical:?}"
        );
    }

    #[test]
    fn no_label_is_empty_or_the_key_echoed_back() {
        for (key, ru, uz) in LABELS {
            assert!(!ru.is_empty() && !uz.is_empty(), "empty label for {key}");
            assert_ne!(ru, key, "the RU label for {key} is the key itself");
            assert_ne!(uz, key, "the UZ label for {key} is the key itself");
        }
    }

    #[test]
    fn keys_are_unique() {
        let mut seen = BTreeSet::new();
        for (key, _, _) in LABELS {
            assert!(seen.insert(*key), "duplicate label entry for {key}");
        }
    }
}
