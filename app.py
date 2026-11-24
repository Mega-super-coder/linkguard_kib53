# -*- coding: utf-8 -*-
"""
LinkGuard v1.0 — локальный аудитор публичных ссылок на корпоративные документы.

УЧЕБНЫЙ MVP. Работает ИСКЛЮЧИТЕЛЬНО на синтетических данных:
- не делает сетевых запросов;
- не открывает проверяемые ссылки;
- не изменяет права доступа к реальным системам.

Стек: Python + Streamlit + Pandas.
Запуск: streamlit run app.py
"""

import io
import json

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# Константы и схема данных
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = [
    "document_name",
    "category",
    "owner",
    "confidentiality",
    "access_type",
    "permissions",
    "has_expiration",
    "project_status",
]

# Допустимые значения полей (для нормализации и мягкой валидации)
CONFIDENTIALITY_LEVELS = ["Публичный", "Внутренний", "Конфиденциальный", "Строго конфиденциальный"]
ACCESS_TYPES = ["Внутренний", "Внешний", "Публичный"]
PERMISSIONS = ["Просмотр", "Редактирование"]
PROJECT_STATUSES = ["В работе", "Завершен"]

# Признаки «истинности» для поля has_expiration (поддержка True/False, Да/Нет, 1/0)
TRUE_TOKENS = {"true", "да", "yes", "1", "истина"}
FALSE_TOKENS = {"false", "нет", "no", "0", "ложь"}

# Порядок уровней риска — используется и для сортировки, и для цветов
RISK_ORDER = {"Критический": 0, "Высокий": 1, "Средний": 2}

RISK_COLORS = {
    "Критический": "#d32f2f",
    "Высокий": "#f57c00",
    "Средний": "#fbc02d",
}

st.set_page_config(
    page_title="LinkGuard — аудит публичных ссылок",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Загрузка и валидация данных
# ---------------------------------------------------------------------------

def normalize_has_expiration(value) -> bool | None:
    """
    Приводит значение has_expiration к булеву типу.
    Возвращает None, если значение пустое или не распознано.
    """
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    token = str(value).strip().lower()
    if token in TRUE_TOKENS:
        return True
    if token in FALSE_TOKENS:
        return False
    return None


def load_uploaded_file(uploaded_file) -> pd.DataFrame:
    """
    Загружает CSV или JSON в DataFrame.
    Выбрасывает ValueError с понятным сообщением при любой проблеме —
    приложение не должно «падать» на кривом файле.
    """
    name = uploaded_file.name.lower()
    try:
        if name.endswith(".csv"):
            # sep=None + engine='python' — автоопределение разделителя (; , \t)
            df = pd.read_csv(uploaded_file, sep=None, engine="python", encoding="utf-8-sig")
        elif name.endswith(".json"):
            raw = json.load(io.TextIOWrapper(uploaded_file, encoding="utf-8"))
            if isinstance(raw, dict):
                # JSON вида {"rows": [...]} или одиночный объект
                raw = raw.get("rows", raw.get("data", [raw]))
            df = pd.DataFrame(raw)
        else:
            raise ValueError(
                f"Неподдерживаемый формат файла: '{uploaded_file.name}'. "
                "Ожидается .csv или .json."
            )
    except ValueError:
        raise  # наше собственное сообщение прокидываем как есть
    except Exception as exc:
        raise ValueError(
            f"Не удалось прочитать файл '{uploaded_file.name}'. "
            f"Причина: {type(exc).__name__}: {exc}. "
            "Убедитесь, что это корректный CSV/JSON в кодировке UTF-8."
        ) from exc

    # Проверка обязательных колонок
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(
            "В файле отсутствуют обязательные колонки: "
            + ", ".join(f"'{c}'" for c in missing)
            + ". Ожидаемая схема: " + ", ".join(REQUIRED_COLUMNS)
        )
    return df


# ---------------------------------------------------------------------------
# Движок правил (Rules Engine)
# ---------------------------------------------------------------------------

def run_audit(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Проверяет каждую строку реестра документов по правилам безопасности.

    Возвращает:
      - findings: DataFrame найденных нарушений
        (document_name, category, owner, rule_id, reason, risk_level, recommendation)
      - warnings: DataFrame строк с предупреждениями о данных
        (document_name, field, message)
    """
    findings = []
    warnings = []

    for idx, row in df.iterrows():
        doc_name = str(row.get("document_name", f"строка {idx + 1}")).strip() or f"строка {idx + 1}"

        # --- Нормализация полей и сбор предупреждений о пустых значениях ---
        confidentiality = str(row.get("confidentiality", "")).strip()
        access_type = str(row.get("access_type", "")).strip()
        permissions = str(row.get("permissions", "")).strip()
        project_status = str(row.get("project_status", "")).strip()
        has_expiration = normalize_has_expiration(row.get("has_expiration"))

        for field, value in [
            ("confidentiality", confidentiality),
            ("access_type", access_type),
            ("permissions", permissions),
            ("project_status", project_status),
        ]:
            if not value or value.lower() == "nan":
                warnings.append({
                    "document_name": doc_name,
                    "field": field,
                    "message": f"Пустое значение в поле '{field}' — строка пропущена в проверках, требующих это поле.",
                })

        if has_expiration is None:
            warnings.append({
                "document_name": doc_name,
                "field": "has_expiration",
                "message": "Не распознано значение has_expiration (ожидается Да/Нет или True/False) — "
                           "Правило 3 для этой строки не применялось.",
            })

        common = {
            "document_name": doc_name,
            "category": str(row.get("category", "")).strip(),
            "owner": str(row.get("owner", "")).strip(),
        }

        # --- Правило 1 (Критический): публичный доступ к конфиденциальному документу ---
        if access_type == "Публичный" and confidentiality in ("Конфиденциальный", "Строго конфиденциальный"):
            findings.append({
                **common,
                "rule_id": "R1",
                "reason": f"Публичная ссылка на документ с уровнем конфиденциальности «{confidentiality}»",
                "risk_level": "Критический",
                "recommendation": "Немедленно сменить тип доступа на «Внутренний» и отозвать публичную ссылку",
            })

        # --- Правило 2 (Высокий): редактирование по внешней/публичной ссылке ---
        if permissions == "Редактирование" and access_type in ("Публичный", "Внешний"):
            findings.append({
                **common,
                "rule_id": "R2",
                "reason": f"Права «{permissions}» по ссылке с типом доступа «{access_type}»",
                "risk_level": "Высокий",
                "recommendation": "Снизить права до «Просмотр» либо сменить тип доступа на «Внутренний»",
            })

        # --- Правило 3 (Средний): внешняя ссылка без срока действия ---
        if access_type == "Внешний" and has_expiration is False:
            findings.append({
                **common,
                "rule_id": "R3",
                "reason": "Внешняя ссылка без ограничения срока действия",
                "risk_level": "Средний",
                "recommendation": "Установить срок действия ссылки (например, 7–30 дней) и дату автоматического отзыва",
            })

        # --- Правило 4 (Средний): доступ к документам завершённого проекта ---
        if project_status == "Завершен" and access_type != "Внутренний":
            findings.append({
                **common,
                "rule_id": "R4",
                "reason": f"Проект завершён, но ссылка остаётся «{access_type}» (избыточный доступ)",
                "risk_level": "Средний",
                "recommendation": "Отозвать внешнюю/публичную ссылку или перевести документ в архив с внутренним доступом",
            })

    findings_df = pd.DataFrame(findings, columns=[
        "document_name", "category", "owner", "rule_id", "reason", "risk_level", "recommendation",
    ])
    warnings_df = pd.DataFrame(warnings, columns=["document_name", "field", "message"])

    if not findings_df.empty:
        findings_df["_sort"] = findings_df["risk_level"].map(RISK_ORDER)
        findings_df = findings_df.sort_values(["_sort", "document_name"]).drop(columns="_sort")

    return findings_df, warnings_df


# ---------------------------------------------------------------------------
# Интерфейс
# ---------------------------------------------------------------------------

st.title("🛡️ LinkGuard — аудит публичных ссылок на корпоративные документы")
st.caption(
    "Локальный учебный MVP · только синтетические данные · "
    "нет сетевых запросов, ссылки не открываются, права не изменяются"
)

# --- Главная страница: загрузка файла ---
uploaded = st.file_uploader(
    "Загрузите реестр документов (.csv или .json)",
    type=["csv", "json"],
    help="Ожидаемые колонки: " + ", ".join(REQUIRED_COLUMNS),
)

# Демо-данные, если файл не загружен
if uploaded is None:
    st.info("Файл не загружен. Для быстрого знакомства можно запустить аудит на встроенных синтетических демо-данных.")
    use_demo = st.button("▶️ Запустить на демо-данных")
    df = None
    if use_demo:
        df = pd.DataFrame([
            {"document_name": "Презентация_брендбук_v3.pdf", "category": "Маркетинг", "owner": "А. Смирнова",
             "confidentiality": "Публичный", "access_type": "Публичный", "permissions": "Просмотр",
             "has_expiration": True, "project_status": "В работе"},
            {"document_name": "Финмодель_клиента_Q3.xlsx", "category": "Финансы", "owner": "Д. Орлов",
             "confidentiality": "Конфиденциальный", "access_type": "Публичный", "permissions": "Просмотр",
             "has_expiration": True, "project_status": "В работе"},
            {"document_name": "Бриф_кампании_осень.docx", "category": "Маркетинг", "owner": "М. Котова",
             "confidentiality": "Внутренний", "access_type": "Внешний", "permissions": "Редактирование",
             "has_expiration": True, "project_status": "В работе"},
            {"document_name": "Договор_подряда_2026.pdf", "category": "Юридические документы", "owner": "И. Гусев",
             "confidentiality": "Конфиденциальный", "access_type": "Внешний", "permissions": "Просмотр",
             "has_expiration": False, "project_status": "В работе"},
            {"document_name": "Отчет_запуск_продукта.pptx", "category": "Аналитика", "owner": "Е. Лебедева",
             "confidentiality": "Внутренний", "access_type": "Внешний", "permissions": "Просмотр",
             "has_expiration": True, "project_status": "Завершен"},
        ])
else:
    try:
        df = load_uploaded_file(uploaded)
    except ValueError as exc:
        st.error(f"⚠️ {exc}")
        df = None

# --- Дашборд ---
if df is not None:
    st.divider()
    findings_df, warnings_df = run_audit(df)

    total_docs = len(df)
    total_findings = len(findings_df)
    risk_counts = (
        findings_df["risk_level"].value_counts().reindex(["Критический", "Высокий", "Средний"], fill_value=0)
        if not findings_df.empty else pd.Series({"Критический": 0, "Высокий": 0, "Средний": 0})
    )

    st.subheader("📊 Дашборд")
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Проверено документов", total_docs)
    col2.metric("Найдено нарушений", total_findings)
    col3.metric("🔴 Критические", int(risk_counts["Критический"]))
    col4.metric("🟠 Высокие", int(risk_counts["Высокий"]))
    col5.metric("🟡 Средние", int(risk_counts["Средний"]))

    if not findings_df.empty:
        st.bar_chart(
            risk_counts.rename("Нарушения"),
            color="#d32f2f",
            horizontal=True,
        )

    # --- Предупреждения по качеству данных ---
    if not warnings_df.empty:
        with st.expander(f"⚠️ Предупреждения по данным ({len(warnings_df)})", expanded=False):
            st.dataframe(warnings_df, use_container_width=True, hide_index=True)

    # --- Таблица результатов с фильтром ---
    st.subheader("📋 Найденные нарушения")
    if findings_df.empty:
        st.success("✅ Нарушений не обнаружено. Реестр соответствует правилам.")
    else:
        filter_levels = st.multiselect(
            "Фильтр по уровню риска",
            options=["Критический", "Высокий", "Средний"],
            default=["Критический", "Высокий", "Средний"],
        )
        filtered = findings_df[findings_df["risk_level"].isin(filter_levels)]

        def style_risk(row):
            color = RISK_COLORS.get(row["risk_level"], "#ffffff")
            return [f"background-color: {color}22"] * len(row)  # 22 = ~13% прозрачность

        st.dataframe(
            filtered.style.apply(style_risk, axis=1),
            use_container_width=True,
            hide_index=True,
        )

        # --- Экспорт ---
        csv_bytes = filtered.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            label="⬇️ Скачать отчёт (CSV)",
            data=csv_bytes,
            file_name="linkguard_report.csv",
            mime="text/csv",
        )

    # --- Полный реестр (сворачиваемый) ---
    with st.expander("Просмотреть загруженный реестр целиком"):
        st.dataframe(df, use_container_width=True, hide_index=True)

st.divider()
st.caption(
    "LinkGuard · учебный проект по дисциплине «Безопасность предпринимательской деятельности» · "
    "приложение анализирует только локальный файл и ничего никуда не отправляет"
)
