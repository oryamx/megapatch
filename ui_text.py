"""Every user-facing text of the dashboard, in English and Spanish.

Only words change with the language. Data never does: evidence files, CVE/CWE ids, finding titles
from the scanners, code, commands, diffs, PoC and test output, and every number are shown exactly as
recorded. Text written by the model during a run (public-evidence summaries) and by the analysis
engine (stage details) is data too, so it stays as recorded.

check_language.py verifies that every key exists in both languages with the same placeholders, and
that switching the language leaves the data on the page unchanged.
"""
import re

from evidence_utils import describe_export

LANGS = {"en": "English", "es": "Español"}

TEXT = {
    # ---------- sidebar ----------
    "lang_label": {"en": "Language / Idioma", "es": "Language / Idioma"},
    "hidden_runs": {
        "en": "{n} other run(s) hidden: they describe a different findings inventory or scoring set-up.",
        "es": "Se ocultan {n} corrida(s): describen otro inventario de hallazgos u otra configuración del puntaje.",
    },
    "run_to_display": {"en": "Run to display", "es": "Corrida a mostrar"},
    "run_golden": {"en": "Recorded demo run", "es": "Corrida de demostración grabada"},
    "run_repair": {"en": "Recorded run with a repaired patch", "es": "Corrida grabada con un parche reparado"},
    "run_human": {"en": "Run approved by a person", "es": "Corrida aprobada por una persona"},
    "run_b": {"en": "Recorded run with the current judge", "es": "Corrida grabada con el juez actual"},
    "run_session": {"en": "Interactive session {sid}", "es": "Sesión interactiva {sid}"},
    "kind_unreadable": {"en": "unreadable", "es": "ilegible"},
    "kind_no_patches": {"en": "no patches", "es": "sin parches"},
    "kind_human": {"en": "human approval", "es": "aprobación humana"},
    "kind_auto": {"en": "automatic approval (--yes)", "es": "aprobación automática (--yes)"},
    "kind_none": {"en": "no export decision (judge rejected)", "es": "sin decisión de exportación (el juez rechazó)"},
    "kind_mixed": {"en": "mixed or unrecorded approval", "es": "aprobación mixta o no registrada"},
    # ---------- header ----------
    "tagline": {
        "en": "Rank what matters, prove it is exploitable by running the exploit, patch it, "
              "and re-run the same exploit. The score proposes; execution disposes.",
        "es": "Prioriza lo que importa, demuestra que es explotable ejecutando el exploit, parchéalo "
              "y vuelve a ejecutar el mismo exploit. El puntaje propone; la ejecución decide.",
    },
    "recorded_notice": {
        "en": "**You are looking at a recorded run** (`{file}`). This page does not analyze anything live: it shows "
              "results recorded earlier on our practice app. A new analysis runs only on your machine, with your own "
              "credentials: `python megapatch.py`, or the *Analyze (local)* tab.",
        "es": "**Estás viendo una corrida grabada** (`{file}`). Esta página no analiza nada en vivo: muestra "
              "resultados registrados antes sobre nuestra app de práctica. Un análisis nuevo solo se ejecuta en tu "
              "máquina, con tus propias credenciales: `python megapatch.py`, o la pestaña *Analizar (local)*.",
    },
    "no_run": {
        "en": "No run found yet. Run `python megapatch.py` to create one.",
        "es": "Todavía no hay corridas. Ejecuta `python megapatch.py` para crear una.",
    },
    # ---------- how to use ----------
    "howto_title": {"en": "How to use MegaPatch", "es": "Cómo se usa MegaPatch"},
    "howto_provides": {
        "en": "**What your team provides**\n\n"
              "- To scan your own project: only its folder, on your machine (*Your repository (local)* tab), and "
              "the answers to four exposure questions.\n"
              "- Scanner output: pip-audit (dependencies) and Bandit (code), as JSON.\n"
              "- Asset context: which asset each package or file belongs to and how exposed it is "
              "(`data/assets.json`).\n"
              "- The application, its functional tests and a PoC per vulnerability class. Today: three classes, "
              "for the bundled practice app only.\n"
              "- For a new run: a Nebius Token Factory key with Sandboxes access (Tavily is optional).",
        "es": "**Qué aporta el equipo**\n\n"
              "- Para escanear su propio proyecto: solo su carpeta, en su máquina (pestaña *Tu repositorio "
              "(local)*), y las respuestas a cuatro preguntas de exposición.\n"
              "- La salida de los escáneres: pip-audit (dependencias) y Bandit (código), en JSON.\n"
              "- El contexto de los activos: a qué activo pertenece cada paquete o archivo y cuán expuesto está "
              "(`data/assets.json`).\n"
              "- La aplicación, sus pruebas funcionales y un PoC por clase de vulnerabilidad. Hoy: tres clases, "
              "solo para la app de práctica incluida.\n"
              "- Para una corrida nueva: una clave de Nebius Token Factory con acceso a Sandboxes (Tavily es "
              "opcional).",
    },
    "howto_does": {
        "en": "**What MegaPatch does**\n\n"
              "1. Prioritize: the ScoreRisk rule ranks every finding.\n"
              "2. Prove: the PoC runs against the app in a Nebius sandbox.\n"
              "3. Patch: NVIDIA Nemotron writes a fix.\n"
              "4. Re-test: the same PoC and the tests judge the fix; a rejected fix gets one repair.\n"
              "5. Approve: a person decides whether the fix is exported.",
        "es": "**Qué hace MegaPatch**\n\n"
              "1. Priorizar: la regla ScoreRisk ordena todos los hallazgos.\n"
              "2. Probar: el PoC se ejecuta contra la app en un sandbox de Nebius.\n"
              "3. Parchear: NVIDIA Nemotron escribe un arreglo.\n"
              "4. Re-probar: el mismo PoC y las pruebas juzgan el arreglo; si lo rechazan, hay un intento de "
              "reparación.\n"
              "5. Aprobar: una persona decide si el arreglo se exporta.",
    },
    "howto_produces": {
        "en": "**What it produces**\n\n"
              "- A ranked queue, with an action band and its basis for every finding.\n"
              "- A verdict for each finding it can verify, with the exploit's output.\n"
              "- A patch (diff) and the result of re-running the same PoC and the tests.\n"
              "- An evidence record (JSON) with the approvals and fingerprints of the inputs and of the judge.",
        "es": "**Qué produce**\n\n"
              "- Una cola ordenada, con una banda de acción y su fundamento para cada hallazgo.\n"
              "- Un veredicto para cada hallazgo que puede verificar, con la salida del exploit.\n"
              "- Un parche (diff) y el resultado de volver a ejecutar el mismo PoC y las pruebas.\n"
              "- Un registro de evidencia (JSON) con las aprobaciones y las huellas de las entradas y del juez.",
    },
    "howto_review": {
        "en": "**What a person must review**\n\n"
              "- The declared exposure and the weights behind the ranking.\n"
              "- Every patch diff, before approving its export.\n"
              "- What the PoC and the tests do not cover: \"accepted by the judge\" is not \"safe in production\".\n"
              "- Findings marked not verifiable: they still need a decision.",
        "es": "**Qué debe revisar una persona**\n\n"
              "- La exposición declarada y los pesos detrás del orden.\n"
              "- Cada diff de parche, antes de aprobar su exportación.\n"
              "- Lo que el PoC y las pruebas no cubren: \"aceptado por el juez\" no es \"seguro en producción\".\n"
              "- Los hallazgos marcados como no verificables: igual necesitan una decisión.",
    },
    # ---------- quick start (inside the how-to block); the commands themselves are in QUICKSTART_COMMANDS ----------
    "qs_title": {"en": "**Quick start**", "es": "**Inicio rápido**"},
    "qs_scope": {
        "en": '**What works today.** The public demo only shows recorded runs. On your own machine, MegaPatch scans any Python project read-only (Bandit for the code, pip-audit for the pinned requirements) and ranks the real findings with their file and line, but it cannot verify or patch them. The PoCs and the patches work only with the bundled practice app (`target_app/`).',
        "es": '**Qué funciona hoy.** La demo pública solo muestra corridas grabadas. En tu propia máquina, MegaPatch escanea cualquier proyecto Python en modo de solo lectura (Bandit para el código, pip-audit para los requisitos fijados) y ordena los hallazgos reales con su archivo y su línea, pero no puede verificarlos ni parchearlos. Los PoC y los parches solo funcionan con la app de práctica incluida (`target_app/`).',
    },
    "qs_install": {
        "en": '**1. Install** MegaPatch and the scanners, at the exact versions a scan checks (`requirements-scan.txt`).',
        "es": '**1. Instala** MegaPatch y los escáneres, en las versiones exactas que comprueba cada escaneo (`requirements-scan.txt`).',
    },
    "qs_scan": {
        "en": '**2. Start the dashboard in local scan mode**, open *Your repository (local)*, type the folder of your project and press *Scan (read-only)*. Nothing from the project is installed, imported or run, its folder is not changed, and every scan is saved in a new folder `analysis/<project>/scans/<scan id>/`. `--server.address 127.0.0.1` only limits incoming connections (the page answers on this machine only); the scan still sends the outgoing requests listed under *What leaves this machine*.',
        "es": '**2. Abre el dashboard en modo de escaneo local**, ve a *Tu repositorio (local)*, escribe la carpeta de tu proyecto y pulsa *Escanear (solo lectura)*. No se instala, importa ni ejecuta nada del proyecto, su carpeta no cambia y cada escaneo se guarda en una carpeta nueva `analysis/<proyecto>/scans/<id del escaneo>/`. `--server.address 127.0.0.1` solo limita las conexiones entrantes (la página responde solo en esta máquina); el escaneo sigue haciendo las consultas salientes indicadas en *Qué sale de esta máquina*.',
    },
    "qs_assets": {
        "en": '**3. Declare the exposure** in the same tab: reachable from the internet, authentication, production, sensitive data. A field left as *Unknown* stays unknown, never "not exposed". Each declaration is saved as a new file in `analysis/<project>/exposure/`; there is no JSON to edit.',
        "es": '**3. Declara la exposición** en la misma pestaña: accesible desde internet, autenticación, producción, datos sensibles. Un campo que dejas como *Desconocido* sigue siendo desconocido, nunca "no expuesto". Cada declaración se guarda como un archivo nuevo en `analysis/<proyecto>/exposure/`; no hay JSON que editar.',
    },
    "qs_rank": {
        "en": "**4. Read the two queues**: dependencies ordered by ScoreRisk, with the data behind each position and a range where data is missing, and code findings ordered by Bandit's severity and confidence. The same without the dashboard:",
        "es": '**4. Lee las dos colas**: las dependencias ordenadas por ScoreRisk, con los datos que sostienen cada posición y un rango donde faltan datos, y los hallazgos de código ordenados por la severidad y la confianza de Bandit. Lo mismo sin el dashboard:',
    },
    "qs_analyze": {
        "en": '**5. Local analysis with Nebius**, practice app only, spends credits. In `.env` (a copy of `.env.example`) set `NEBIUS_API_KEY` and `NEBIUS_PROJECT_ID` (a Token Factory account with Sandboxes access); `TAVILY_API_KEY` is optional and `MEGAPATCH_ENABLE_INTERACTIVE=1` turns on the *Analyze (local)* tab. Without `--yes`, you approve each export.',
        "es": '**5. Análisis local con Nebius**, solo la app de práctica, gasta créditos. En `.env` (una copia de `.env.example`) configura `NEBIUS_API_KEY` y `NEBIUS_PROJECT_ID` (una cuenta de Token Factory con acceso a Sandboxes); `TAVILY_API_KEY` es opcional y `MEGAPATCH_ENABLE_INTERACTIVE=1` activa la pestaña *Analizar (local)*. Sin `--yes`, apruebas cada exportación.',
    },
    "qs_results": {
        "en": '**6. Where the results go.**\n\n- Scans: `analysis/<project>/scans/<scan id>/` (a new folder each time) and exposure declarations in `analysis/<project>/exposure/`; nothing is overwritten and `analysis/` is not committed.\n- `python megapatch.py`: a new record `evidence/run_<UTC time>.json` (or `evidence/NAME.json` with `--save-as NAME`) and the approved diffs in a new folder `out/patches/<run>/`; nothing earlier is replaced.\n- *Analyze (local)*: `evidence/interactive_run_<session>.json` and `out/patches/<session>/<CWE>.diff`; nothing is overwritten.',
        "es": '**6. Dónde quedan los resultados.**\n\n- Escaneos: `analysis/<proyecto>/scans/<id del escaneo>/` (una carpeta nueva cada vez) y las declaraciones de exposición en `analysis/<proyecto>/exposure/`; no se sobrescribe nada y `analysis/` no se sube al repositorio.\n- `python megapatch.py`: un registro nuevo `evidence/run_<hora UTC>.json` (o `evidence/NOMBRE.json` con `--save-as NOMBRE`) y los diffs aprobados en una carpeta nueva `out/patches/<corrida>/`; no se reemplaza nada anterior.\n- *Analizar (local)*: `evidence/interactive_run_<sesión>.json` y `out/patches/<sesión>/<CWE>.diff`; no se sobrescribe nada.',
    },
    # ---------- your repository (local scan tab) ----------
    "tab_repo": {
        "en": 'Your repository (local)',
        "es": 'Tu repositorio (local)',
    },
    "rp_title": {
        "en": 'Scan your Python repository (local, read-only)',
        "es": 'Escanea tu repositorio Python (local, solo lectura)',
    },
    "rp_intro": {
        "en": "MegaPatch runs **Bandit** on the code and **pip-audit** on the pinned requirements of a folder on this machine, at pinned versions, and shows the real findings with their file and line. It never installs, imports or runs the project's code, never changes its folder, and sends no source code anywhere (not to Streamlit, Nebius, Tavily or a model). The findings are not verified by execution and no patch is written.",
        "es": 'MegaPatch ejecuta **Bandit** sobre el código y **pip-audit** sobre los requisitos fijados de una carpeta de esta máquina, en versiones fijadas, y muestra los hallazgos reales con su archivo y su línea. Nunca instala, importa ni ejecuta el código del proyecto, nunca cambia su carpeta y no envía código fuente a ninguna parte (ni a Streamlit, ni a Nebius, ni a Tavily, ni a un modelo). Los hallazgos no se verifican ejecutándolos y no se escribe ningún parche.',
    },
    "rp_off": {
        "en": 'Scanning runs only on your own machine: `pip install -r requirements-scan.txt`, then `streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan`. The address only limits who can open the page; a scan still queries PyPI and, with threat data, CISA, FIRST and NVD. The public demo is read-only and has no scans.',
        "es": 'El escaneo solo funciona en tu propia máquina: `pip install -r requirements-scan.txt` y luego `streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan`. La dirección solo limita quién puede abrir la página; un escaneo sigue consultando PyPI y, con datos de amenazas, CISA, FIRST y NVD. La demo pública es de solo lectura y no tiene escaneos.',
    },
    "rp_sidebar_on": {
        "en": '**Local scan mode.** Open the *Your repository (local)* tab.',
        "es": '**Modo de escaneo local.** Abre la pestaña *Tu repositorio (local)*.',
    },
    "rp_sidebar_refused": {
        "en": '**Local scan mode refused.** See the *Your repository (local)* tab.',
        "es": '**Modo de escaneo local rechazado.** Mira la pestaña *Tu repositorio (local)*.',
    },
    "rp_refused_not_loopback": {
        "en": '**Scanning is off: this server also listens on network interfaces.** The local scan mode only works when the dashboard listens on this machine only, so that no other machine can ask it to scan a folder. Stop it and start it with `streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan`. The address only limits incoming connections: a scan still makes its outgoing requests (PyPI and, with threat data, CISA, FIRST and NVD).',
        "es": '**El escaneo está desactivado: este servidor también escucha en interfaces de red.** El modo de escaneo local solo funciona cuando el dashboard escucha únicamente en esta máquina, para que ninguna otra máquina pueda pedirle que escanee una carpeta. Detenlo y arráncalo con `streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan`. La dirección solo limita las conexiones entrantes: un escaneo sigue haciendo sus consultas salientes (PyPI y, con datos de amenazas, CISA, FIRST y NVD).',
    },
    "rp_refused_remote": {
        "en": '**Scanning is off for this session:** it does not come from this machine. Open the dashboard on the machine where it runs, at http://127.0.0.1.',
        "es": '**El escaneo está desactivado para esta sesión:** no viene de esta máquina. Abre el dashboard en la máquina donde se ejecuta, en http://127.0.0.1.',
    },
    "rp_step1": {
        "en": '1. Choose the folder',
        "es": '1. Elige la carpeta',
    },
    "rp_path": {
        "en": 'Folder of the project (full path)',
        "es": 'Carpeta del proyecto (ruta completa)',
    },
    "rp_project": {
        "en": 'Project name (optional; by default, the folder name)',
        "es": 'Nombre del proyecto (opcional; por defecto, el nombre de la carpeta)',
    },
    "rp_threat": {
        "en": 'Download public threat data for the CVEs found (CISA KEV, FIRST EPSS, NVD): roughly 7 to 12 seconds per CVE, depending on NVD',
        "es": 'Descargar datos públicos de amenazas para los CVE encontrados (CISA KEV, FIRST EPSS, NVD): aproximadamente de 7 a 12 segundos por CVE, según NVD',
    },
    "rp_sent": {
        "en": "**What leaves this machine:** pip-audit sends the name and version of each pinned package to PyPI's JSON API. With threat data, the CISA KEV catalog is downloaded (nothing is sent) and the CVE ids go to FIRST EPSS and, one per request, to NVD. Nothing else: no source code and no file names. Bandit uses no network.",
        "es": '**Qué sale de esta máquina:** pip-audit envía el nombre y la versión de cada paquete fijado a la API JSON de PyPI. Con los datos de amenazas, se descarga el catálogo CISA KEV (no se envía nada) y los identificadores CVE van a FIRST EPSS y, uno por consulta, a NVD. Nada más: ni código fuente ni nombres de archivos. Bandit no usa la red.',
    },
    "rp_scan_button": {
        "en": 'Scan (read-only)',
        "es": 'Escanear (solo lectura)',
    },
    "rp_running": {
        "en": 'Scanning {folder} ...',
        "es": 'Escaneando {folder} ...',
    },
    "rp_step_survey": {
        "en": 'Listing the folder: exclusions, and the size and time of every file',
        "es": 'Listando la carpeta: exclusiones, y tamaño y fecha de cada archivo',
    },
    "rp_step_requirements": {
        "en": 'Requirements files found: {n}',
        "es": 'Archivos de requisitos encontrados: {n}',
    },
    "rp_step_pip_audit": {
        "en": 'pip-audit: {n} pinned packages',
        "es": 'pip-audit: {n} paquetes fijados',
    },
    "rp_step_bandit": {
        "en": 'Bandit: parsing the Python files',
        "es": 'Bandit: analizando los archivos Python',
    },
    "rp_step_threat": {
        "en": 'Threat data for {n} CVEs',
        "es": 'Datos de amenazas para {n} CVE',
    },
    "rp_step_threat_kev": {
        "en": 'CISA KEV catalog',
        "es": 'Catálogo CISA KEV',
    },
    "rp_step_threat_epss": {
        "en": 'FIRST EPSS',
        "es": 'FIRST EPSS',
    },
    "rp_step_threat_nvd": {
        "en": 'NVD {i}/{n}: {cve}',
        "es": 'NVD {i}/{n}: {cve}',
    },
    "rp_step_verify": {
        "en": 'Checking that the folder did not change',
        "es": 'Comprobando que la carpeta no cambió',
    },
    "rp_done": {
        "en": 'Scan {id} saved: {deps} dependency findings and {code} code findings.',
        "es": 'Escaneo {id} guardado: {deps} hallazgos de dependencias y {code} de código.',
    },
    "rp_failed": {
        "en": 'The scan did not finish: {error}',
        "es": 'El escaneo no terminó: {error}',
    },
    "rp_err_not_a_folder": {
        "en": '{path} is not a folder.',
        "es": '{path} no es una carpeta.',
    },
    "rp_err_contains_analysis": {
        "en": 'MegaPatch writes its results in {root}, which is inside {repo}: scanning it would change the folder being analyzed. Choose the project folder itself.',
        "es": 'MegaPatch escribe sus resultados en {root}, que está dentro de {repo}: escanearla cambiaría la carpeta analizada. Elige la carpeta del proyecto.',
    },
    "rp_err_inside_analysis": {
        "en": "{repo} is inside MegaPatch's own results folder.",
        "es": '{repo} está dentro de la carpeta de resultados de MegaPatch.',
    },
    "rp_err_bad_project": {
        "en": "Project name: letters, digits, '-' and '_' only, starting with a letter or a digit (at most 40).",
        "es": "Nombre del proyecto: solo letras, dígitos, '-' y '_', empezando por una letra o un dígito (máximo 40).",
    },
    "rp_err_scanners": {
        "en": 'The scanners are not the pinned versions ({wrong}). Install them with `pip install -r requirements-scan.txt`.',
        "es": 'Los escáneres no están en las versiones fijadas ({wrong}). Instálalos con `pip install -r requirements-scan.txt`.',
    },
    "rp_err_requirements_file": {
        "en": '{file} is not a file inside the repository.',
        "es": '{file} no es un archivo dentro del repositorio.',
    },
    "rp_err_tool_failed": {
        "en": '{tool} did not produce a result: {detail}',
        "es": '{tool} no produjo un resultado: {detail}',
    },
    "rp_err_no_project": {
        "en": 'No scan of project {project} yet.',
        "es": 'Todavía no hay escaneos del proyecto {project}.',
    },
    "rp_none": {
        "en": 'No scan on this machine yet.',
        "es": 'Todavía no hay escaneos en esta máquina.',
    },
    "rp_select_project": {
        "en": 'Project',
        "es": 'Proyecto',
    },
    "rp_select_scan": {
        "en": 'Scan',
        "es": 'Escaneo',
    },
    "rp_scan_label": {
        "en": '{when} UTC · {id}',
        "es": '{when} UTC · {id}',
    },
    "rp_incomplete": {
        "en": '{n} unfinished scan(s) of this project are not shown: they stopped before the scan was recorded as complete.',
        "es": 'No se muestran {n} escaneo(s) sin terminar de este proyecto: se detuvieron antes de registrarse como completos.',
    },
    "rp_step2": {
        "en": '2. Declare the exposure of {project}',
        "es": '2. Declara la exposición de {project}',
    },
    "rp_x_intro": {
        "en": 'You declare the exposure; MegaPatch does not discover it. A field left as *Unknown* stays unknown: it is never read as "not exposed", and the score shows the range it could add. Each declaration is saved as a new file and the earlier ones are kept.',
        "es": 'La exposición la declaras tú; MegaPatch no la descubre. Un campo que dejas como *Desconocido* sigue siendo desconocido: nunca se interpreta como "no expuesto", y el puntaje muestra el rango que podría sumar. Cada declaración se guarda como un archivo nuevo y las anteriores se conservan.',
    },
    "rp_x_internet": {
        "en": 'Reachable from the internet?',
        "es": '¿Accesible desde internet?',
    },
    "rp_x_auth": {
        "en": 'Requires authentication?',
        "es": '¿Requiere autenticación?',
    },
    "rp_x_env": {
        "en": 'Environment',
        "es": 'Entorno',
    },
    "rp_x_sensitive": {
        "en": 'Handles sensitive data?',
        "es": '¿Maneja datos sensibles?',
    },
    "rp_x_unknown": {
        "en": 'Unknown (not declared)',
        "es": 'Desconocido (sin declarar)',
    },
    "rp_x_yes": {
        "en": 'Yes',
        "es": 'Sí',
    },
    "rp_x_no": {
        "en": 'No',
        "es": 'No',
    },
    "rp_x_production": {
        "en": 'Production',
        "es": 'Producción',
    },
    "rp_x_non_production": {
        "en": 'Not production',
        "es": 'No es producción',
    },
    "rp_x_save": {
        "en": 'Save the declaration',
        "es": 'Guardar la declaración',
    },
    "rp_x_saved": {
        "en": 'Declaration {id} saved.',
        "es": 'Declaración {id} guardada.',
    },
    "rp_x_current": {
        "en": 'Declared {when} UTC: {summary}.',
        "es": 'Declarado el {when} UTC: {summary}.',
    },
    "rp_x_none": {
        "en": 'Nothing declared yet for {project}: the four fields are unknown.',
        "es": 'Todavía no hay nada declarado para {project}: los cuatro campos son desconocidos.',
    },
    "rp_step3": {
        "en": '3. Results',
        "es": '3. Resultados',
    },
    "rp_meta": {
        "en": 'Folder `{folder}`{commit} · scan `{id}` · {when} UTC · {scanners} · threat data: {threat}',
        "es": 'Carpeta `{folder}`{commit} · escaneo `{id}` · {when} UTC · {scanners} · datos de amenazas: {threat}',
    },
    "rp_commit": {
        "en": ' (commit {c})',
        "es": ' (commit {c})',
    },
    "rp_threat_none": {
        "en": 'not downloaded',
        "es": 'no descargados',
    },
    "rp_check_ok": {
        "en": 'The analyzed folder did not change: {n} files compared before and after (path, size and modification time), excluded folders included.',
        "es": 'La carpeta analizada no cambió: {n} archivos comparados antes y después (ruta, tamaño y fecha de modificación), incluidas las carpetas excluidas.',
    },
    "rp_check_changed": {
        "en": 'The analyzed folder changed during the scan ({files}). The scan does not write there: something else did.',
        "es": 'La carpeta analizada cambió durante el escaneo ({files}). El escaneo no escribe ahí: lo hizo otra cosa.',
    },
    "rp_excluded": {
        "en": 'Left out: {items}.',
        "es": 'Excluido: {items}.',
    },
    "rp_excluded_none": {
        "en": 'Nothing was left out.',
        "es": 'No se excluyó nada.',
    },
    "rp_scope": {
        "en": '**Scanned, not verified.** These findings come from the scanners only: no exploit was run and no patch was written. They are shown in two queues because a dependency advisory and a code finding have no common scale.',
        "es": '**Escaneado, no verificado.** Estos hallazgos vienen solo de los escáneres: no se ejecutó ningún exploit ni se escribió ningún parche. Se muestran en dos colas porque un aviso de dependencia y un hallazgo de código no tienen una escala común.',
    },
    "rp_counts": {
        "en": '**{deps}** dependency findings ({cves} CVEs, {kev} in CISA KEV, {prov} with a provisional position) · **{code}** code findings ({high} high, {medium} medium, {low} low severity; {tests} in test code)',
        "es": '**{deps}** hallazgos de dependencias ({cves} CVE, {kev} en CISA KEV, {prov} con posición provisional) · **{code}** hallazgos de código (severidad {high} alta, {medium} media, {low} baja; {tests} en código de pruebas)',
    },
    "rp_x_summary": {
        "en": 'Exposure: {summary}',
        "es": 'Exposición: {summary}',
    },
    "rp_x_range": {
        "en": 'X between {low} and {high}',
        "es": 'X entre {low} y {high}',
    },
    "rp_x_exact": {
        "en": 'X = {x}',
        "es": 'X = {x}',
    },
    "rp_how_title": {
        "en": 'How each queue is ordered',
        "es": 'Cómo se ordena cada cola',
    },
    "rp_how": {
        "en": "**Dependencies (pip-audit).** ScoreRisk = 100 × (0.5 E + 0.3 X + 0.2 S), the demo's rule. E is the EPSS probability, at least 0.9 for a CVE in CISA KEV; S is the CVSS base score from NVD divided by 10; X is the declared exposure. A missing value is not replaced by a default: it becomes an interval (no EPSS: E between 0 and 1; no CVSS: S between 0 and 1; a field not declared: the X it could add), so the score is a range. The queue follows the guaranteed minimum; a row whose position could change once the missing value is known is marked *provisional*. X is the same for every finding of one repository, so it never changes the order, only the score and the action band.\n\n**Code (Bandit).** Bandit's own severity first, then its confidence (HIGH, MEDIUM, LOW); at the same level, code outside test folders comes first. No number is computed: Bandit's ratings are not CVSS and have no exploitation data, so there is no common scale with the dependency queue.",
        "es": '**Dependencias (pip-audit).** ScoreRisk = 100 × (0,5 E + 0,3 X + 0,2 S), la regla de la demo. E es la probabilidad EPSS, como mínimo 0,9 para un CVE en CISA KEV; S es la puntuación base CVSS de NVD dividida por 10; X es la exposición declarada. Un valor que falta no se reemplaza por uno por defecto: se convierte en un intervalo (sin EPSS: E entre 0 y 1; sin CVSS: S entre 0 y 1; un campo sin declarar: la X que podría sumar), así que el puntaje es un rango. La cola sigue el mínimo garantizado; una fila cuya posición podría cambiar al conocerse el dato que falta se marca como *provisional*. X es la misma para todos los hallazgos de un repositorio, así que nunca cambia el orden, solo el puntaje y la banda de acción.\n\n**Código (Bandit).** Primero la severidad de Bandit y luego su confianza (HIGH, MEDIUM, LOW); al mismo nivel, el código fuera de las carpetas de pruebas va primero. No se calcula ningún número: las valoraciones de Bandit no son CVSS ni tienen datos de explotación, así que no hay una escala común con la cola de dependencias.',
    },
    "rp_deps_title": {
        "en": 'Dependencies (pip-audit): {n}',
        "es": 'Dependencias (pip-audit): {n}',
    },
    "rp_deps_none": {
        "en": 'pip-audit found no known vulnerability in the {n} pinned packages.',
        "es": 'pip-audit no encontró ninguna vulnerabilidad conocida en los {n} paquetes fijados.',
    },
    "rp_deps_nopins": {
        "en": 'No requirement pinned with `==` was found, so pip-audit had nothing to check.',
        "es": 'No se encontró ningún requisito fijado con `==`, así que pip-audit no tenía nada que revisar.',
    },
    "rp_code_title": {
        "en": 'Code (Bandit): {n}',
        "es": 'Código (Bandit): {n}',
    },
    "rp_code_none": {
        "en": 'Bandit reported nothing in the {n} Python files it analyzed.',
        "es": 'Bandit no reportó nada en los {n} archivos Python que analizó.',
    },
    "rp_col_package": {
        "en": 'Package',
        "es": 'Paquete',
    },
    "rp_col_advisory": {
        "en": 'Advisory',
        "es": 'Aviso',
    },
    "rp_col_manifest": {
        "en": 'Pinned at',
        "es": 'Fijado en',
    },
    "rp_col_band": {
        "en": 'Band',
        "es": 'Banda',
    },
    "rp_col_basis": {
        "en": 'Why here',
        "es": 'Por qué aquí',
    },
    "rp_col_basis_help": {
        "en": 'The data behind the position; a dash means the value is not available',
        "es": 'Los datos que sostienen la posición; un guion significa que el valor no está disponible',
    },
    "rp_col_fix": {
        "en": 'Fixed in',
        "es": 'Corregido en',
    },
    "rp_col_level": {
        "en": 'Severity / confidence',
        "es": 'Severidad / confianza',
    },
    "rp_col_level_help": {
        "en": "Bandit's own ratings, not CVSS",
        "es": 'Valoraciones propias de Bandit, no son CVSS',
    },
    "rp_col_finding": {
        "en": 'Finding',
        "es": 'Hallazgo',
    },
    "rp_col_file": {
        "en": 'File',
        "es": 'Archivo',
    },
    "rp_col_line": {
        "en": 'Line',
        "es": 'Línea',
    },
    "rp_col_tests": {
        "en": 'Test code',
        "es": 'Código de pruebas',
    },
    "rp_b_kev": {
        "en": 'in CISA KEV',
        "es": 'en CISA KEV',
    },
    "rp_b_epss": {
        "en": 'EPSS {v}',
        "es": 'EPSS {v}',
    },
    "rp_b_cvss": {
        "en": 'CVSS {v}',
        "es": 'CVSS {v}',
    },
    "rp_b_missing": {
        "en": 'no {what}',
        "es": 'sin {what}',
    },
    "rp_b_nocve": {
        "en": 'no CVE: EPSS, KEV and NVD do not apply',
        "es": 'sin CVE: EPSS, KEV y NVD no se aplican',
    },
    "rp_b_provisional": {
        "en": 'provisional',
        "es": 'provisional',
    },
    "rp_b_tests": {
        "en": 'test code',
        "es": 'código de pruebas',
    },
    "rp_detail": {
        "en": 'Explain one finding',
        "es": 'Explicar un hallazgo',
    },
    "rp_detail_dep_label": {
        "en": 'Dependency #{rank}: {package} {version} · {advisory}',
        "es": 'Dependencia #{rank}: {package} {version} · {advisory}',
    },
    "rp_detail_code_label": {
        "en": 'Code #{rank}: {file}:{line} · {test}',
        "es": 'Código #{rank}: {file}:{line} · {test}',
    },
    "rp_ex_dep_head": {
        "en": '**#{rank} in the dependency queue.** `{package} {version}`, pinned at `{where}`. Advisory {advisory}{aliases}.',
        "es": '**#{rank} en la cola de dependencias.** `{package} {version}`, fijado en `{where}`. Aviso {advisory}{aliases}.',
    },
    "rp_ex_e_kev": {
        "en": 'Exploitation (E): in CISA KEV, so at least {floor}{epss}.',
        "es": 'Explotación (E): está en CISA KEV, así que como mínimo {floor}{epss}.',
    },
    "rp_ex_e_epss": {
        "en": 'Exploitation (E): EPSS {v} (percentile {p}).',
        "es": 'Explotación (E): EPSS {v} (percentil {p}).',
    },
    "rp_ex_e_none": {
        "en": 'Exploitation (E): no EPSS value, so E is between 0 and 1.',
        "es": 'Explotación (E): sin valor EPSS, así que E está entre 0 y 1.',
    },
    "rp_ex_e_nocve": {
        "en": 'Exploitation (E): the advisory has no CVE, so EPSS and KEV do not apply; E is between 0 and 1.',
        "es": 'Explotación (E): el aviso no tiene CVE, así que EPSS y KEV no se aplican; E está entre 0 y 1.',
    },
    "rp_ex_s": {
        "en": 'Severity (S): CVSS {v} (NVD){cwe}.',
        "es": 'Severidad (S): CVSS {v} (NVD){cwe}.',
    },
    "rp_ex_s_none": {
        "en": 'Severity (S): no CVSS in NVD, so S is between 0 and 1.',
        "es": 'Severidad (S): sin CVSS en NVD, así que S está entre 0 y 1.',
    },
    "rp_ex_x": {
        "en": 'Exposure (X): {x}. The same for every finding of this repository: it changes the score, not the order.',
        "es": 'Exposición (X): {x}. Es la misma para todos los hallazgos de este repositorio: cambia el puntaje, no el orden.',
    },
    "rp_ex_score": {
        "en": 'ScoreRisk: {score}. Position: {position}.',
        "es": 'ScoreRisk: {score}. Posición: {position}.',
    },
    "rp_ex_exact": {
        "en": 'exact',
        "es": 'exacta',
    },
    "rp_ex_provisional": {
        "en": 'provisional, it could change once {missing} is known (the queue follows the guaranteed minimum)',
        "es": 'provisional, podría cambiar cuando se conozca {missing} (la cola sigue el mínimo garantizado)',
    },
    "rp_ex_band": {
        "en": 'Action band: {bands}.',
        "es": 'Banda de acción: {bands}.',
    },
    "rp_ex_band_depends": {
        "en": 'Action band: {bands}, depending on {what}.',
        "es": 'Banda de acción: {bands}, según {what}.',
    },
    "rp_ex_band_internet": {
        "en": 'whether it is reachable from the internet',
        "es": 'si es accesible desde internet',
    },
    "rp_ex_band_epss": {
        "en": 'the EPSS value',
        "es": 'el valor EPSS',
    },
    "rp_ex_fix": {
        "en": 'Fixed in: {versions}.',
        "es": 'Corregido en: {versions}.',
    },
    "rp_ex_nofix": {
        "en": 'No fixed version listed by the advisory.',
        "es": 'El aviso no indica una versión corregida.',
    },
    "rp_ex_summary": {
        "en": 'Advisory text: {text}',
        "es": 'Texto del aviso: {text}',
    },
    "rp_ex_code_head": {
        "en": '**#{rank} in the code queue.** `{where}` · Bandit {test} ({name}){cwe}.',
        "es": '**#{rank} en la cola de código.** `{where}` · Bandit {test} ({name}){cwe}.',
    },
    "rp_ex_code_message": {
        "en": 'Bandit says: {message}',
        "es": 'Bandit dice: {message}',
    },
    "rp_ex_code_position": {
        "en": "Position: Bandit severity {severity}, then confidence {confidence} (Bandit's own ratings, not CVSS){tests}.",
        "es": 'Posición: severidad de Bandit {severity} y luego confianza {confidence} (valoraciones propias de Bandit, no son CVSS){tests}.',
    },
    "rp_ex_code_tests": {
        "en": '; it is test code, so it comes after the other findings of the same level',
        "es": '; es código de pruebas, así que va después de los demás hallazgos del mismo nivel',
    },
    "rp_ex_more": {
        "en": "Bandit's documentation for this check: {url}",
        "es": 'Documentación de Bandit para esta comprobación: {url}',
    },
    "rp_not_audited": {
        "en": 'Not audited ({n})',
        "es": 'No auditado ({n})',
    },
    "rp_col_text": {
        "en": 'Line text',
        "es": 'Texto de la línea',
    },
    "rp_col_reason": {
        "en": 'Reason',
        "es": 'Motivo',
    },
    "rp_manifests": {
        "en": 'Found but not read (this version reads `requirements*.txt` only): {files}.',
        "es": 'Encontrado pero no leído (esta versión solo lee `requirements*.txt`): {files}.',
    },
    "rp_not_parsed": {
        "en": 'Bandit could not parse {n} file(s): {files}.',
        "es": 'Bandit no pudo analizar {n} archivo(s): {files}.',
    },
    "rp_external_title": {
        "en": 'What was queried outside this machine',
        "es": 'Qué se consultó fuera de esta máquina',
    },
    "rp_ext_pypi": {
        "en": 'PyPI JSON API (pip-audit): the name and version of {n} pinned packages',
        "es": 'API JSON de PyPI (pip-audit): el nombre y la versión de {n} paquetes fijados',
    },
    "rp_ext_kev": {
        "en": 'CISA KEV: the whole catalog was downloaded; nothing was sent',
        "es": 'CISA KEV: se descargó el catálogo completo; no se envió nada',
    },
    "rp_ext_epss": {
        "en": 'FIRST EPSS: {n} CVE ids',
        "es": 'FIRST EPSS: {n} identificadores CVE',
    },
    "rp_ext_nvd": {
        "en": 'NVD: {n} CVE ids, one per request',
        "es": 'NVD: {n} identificadores CVE, uno por consulta',
    },
    "rp_ext_bandit": {
        "en": 'Bandit: nothing (it does not use the network)',
        "es": 'Bandit: nada (no usa la red)',
    },
    "rp_ext_none": {
        "en": 'Nothing else: no source code and no file names.',
        "es": 'Nada más: ni código fuente ni nombres de archivos.',
    },
    "rp_not_done": {
        "en": 'No code from the repository was run. The findings come from the scanners only: they were not verified by execution, and no patch was written.',
        "es": 'No se ejecutó código del repositorio. Los hallazgos vienen solo de los escáneres: no se verificaron ejecutándolos y no se escribió ningún parche.',
    },
    "live_title": {
        "en": 'Analyze one finding of the practice app (local)',
        "es": 'Analizar un hallazgo de la app de práctica (local)',
    },
    # ---------- five-step strip ----------
    "step_prioritize": {"en": "Prioritize", "es": "Priorizar"},
    "step_prove": {"en": "Prove", "es": "Probar"},
    "step_patch": {"en": "Patch", "es": "Parchear"},
    "step_retest": {"en": "Re-test", "es": "Re-probar"},
    "step_approve": {"en": "Approve", "es": "Aprobar"},
    "funnel": {
        "en": "{pip} pip-audit entries and {bandit} Bandit results became {findings} distinct findings "
              "({cves} unique CVEs, {kev} in CISA KEV).",
        "es": "{pip} entradas de pip-audit y {bandit} resultados de Bandit se convirtieron en {findings} hallazgos "
              "distintos ({cves} CVE únicos, {kev} en CISA KEV).",
    },
    "s_prioritize_norun": {"en": "**{findings} findings** ranked by ScoreRisk",
                           "es": "**{findings} hallazgos** ordenados por ScoreRisk"},
    "s_prioritize": {"en": "**{findings} findings** ranked by ScoreRisk; the top {top} verified",
                     "es": "**{findings} hallazgos** ordenados por ScoreRisk; se verifican los {top} primeros"},
    "s_prove": {"en": "**{n} confirmed** by an exploit in a Nebius sandbox",
                "es": "**{n} confirmados** por un exploit en un sandbox de Nebius"},
    "s_patch": {"en": "**{n} patch(es)** written by NVIDIA Nemotron on Nebius Token Factory",
                "es": "**{n} parche(s)** escritos por NVIDIA Nemotron en Nebius Token Factory"},
    "s_retest_head": {"en": "Same PoC and tests: **{n} accepted**", "es": "Mismo PoC y pruebas: **{n} aceptados**"},
    "s_retest_repair": {"en": " ({n} after one repair)", "es": " ({n} tras una reparación)"},
    "s_retest_tail": {"en": ", {n} rejected", "es": ", {n} rechazados"},
    "s_approve_human": {"en": "**{a} of {b} approved** by a person before export",
                        "es": "**{a} de {b} aprobados** por una persona antes de exportar"},
    "s_approve_auto": {"en": "**Automatic (`--yes`)**: no person approved these exports",
                       "es": "**Automática (`--yes`)**: ninguna persona aprobó estas exportaciones"},
    "s_approve_mixed": {"en": "Mixed or unrecorded approval: see each patch in the *Walkthrough* tab",
                        "es": "Aprobación mixta o no registrada: revisa cada parche en la pestaña *Recorrido*"},
    "s_approve_none": {"en": "No patch reached the approval step", "es": "Ningún parche llegó al paso de aprobación"},
    "story_detail": {
        "en": "{funnel} Of the top {top}, {unv} have no PoC and are reported as not verifiable, never as safe. "
              "Patches by `{model}`: {calls} calls, about ${cost}.",
        "es": "{funnel} De los {top} primeros, {unv} no tienen PoC y se reportan como no verificables, nunca como "
              "seguros. Parches de `{model}`: {calls} llamadas, cerca de ${cost}.",
    },
    "limits_caption": {
        "en": "Recorded runs on our own practice app, not real-world code. The PoCs call the app in-process (Flask's "
              "test client) inside the sandbox, whose outbound network is not blocked. \"Accepted by the judge\" "
              "means the same PoC and the functional tests passed, not \"safe in production\". The *Walkthrough* tab "
              "follows one finding through all five steps.",
        "es": "Corridas grabadas sobre nuestra propia app de práctica, no sobre código real. Los PoC llaman a la app "
              "en el mismo proceso (con el cliente de pruebas de Flask), dentro del sandbox, cuya red de salida no "
              "está bloqueada. \"Aceptado por el juez\" significa que el mismo PoC y las pruebas funcionales pasaron, "
              "no \"seguro en producción\". La pestaña *Recorrido* sigue un hallazgo por los cinco pasos.",
    },
    "limits_title": {"en": "What you are looking at, and what it does not show",
                     "es": "Qué estás viendo y qué no muestra"},
    "limits_body": {
        "en": """
- **Input:** real scanner output on deliberately chosen input. pip-audit over {pkgs}
  outdated pinned packages reported {pip} entries, {advisories} distinct
  advisories once repeats are removed. Bandit over our practice app reported {bandit} results,
  kept as {bandit_findings} findings (one per class we can verify), and {manual} finding
  comes from manual review. Total: {findings} distinct findings, {cves} unique CVEs,
  {kev} of them in CISA KEV.
- **Declared, not discovered:** which asset each finding belongs to and how exposed it is (a fictional inventory).
- **Verifiable by execution:** three vulnerability classes, only in our own practice app. Everything else is
  ranked and reported as not verifiable, never as safe.
- **The PoCs run in-process** inside the sandbox; they do not test network reachability.
- **Isolation means no secrets and not our machine:** the sandbox's outbound network is not blocked and code runs
  as root inside it.
- **Approval:** runs made with `--yes` skipped every human approval question. Each run's banner says which kind it
  is, read from its own data.
- **Not measured:** there is no precision figure for the ranking.
""",
        "es": """
- **Entrada:** salida real de escáneres sobre una entrada elegida a propósito. pip-audit sobre {pkgs}
  paquetes fijados y desactualizados reportó {pip} entradas, {advisories} avisos distintos una vez
  eliminadas las repeticiones. Bandit sobre nuestra app de práctica reportó {bandit} resultados,
  que quedan en {bandit_findings} hallazgos (uno por clase que podemos verificar), y {manual} hallazgo
  viene de una revisión manual. Total: {findings} hallazgos distintos, {cves} CVE únicos,
  {kev} de ellos en CISA KEV.
- **Declarado, no descubierto:** a qué activo pertenece cada hallazgo y cuán expuesto está (un inventario ficticio).
- **Verificable por ejecución:** tres clases de vulnerabilidad, solo en nuestra propia app de práctica. Todo lo
  demás se ordena y se reporta como no verificable, nunca como seguro.
- **Los PoC se ejecutan dentro del proceso** en el sandbox; no prueban si la app es alcanzable por la red.
- **Aislamiento significa sin secretos y no es nuestra máquina:** la red de salida del sandbox no está bloqueada y
  el código se ejecuta como root dentro de él.
- **Aprobación:** las corridas hechas con `--yes` omitieron todas las preguntas de aprobación humana. El aviso de
  cada corrida dice de qué tipo es, leído de sus propios datos.
- **No medido:** no hay una cifra de precisión para el orden.
""",
    },
    # ---------- headline numbers ----------
    "m_findings": {"en": "Findings ranked", "es": "Hallazgos ordenados"},
    "m_confirmed": {"en": "Confirmed", "es": "Confirmados"},
    "m_confirmed_help": {"en": "Confirmed by exploit: the PoC fired in the sandbox (practice app)",
                         "es": "Confirmados por exploit: el PoC funcionó en el sandbox (app de práctica)"},
    "m_accepted": {"en": "Judge accepted", "es": "Aceptados"},
    "m_accepted_help": {
        "en": "Accepted by the judge version RECORDED IN THIS RUN (judge fingerprint: {rec}; the current judge is "
              "{now}). The patch stopped the same exploit and the functional tests passed; the judge only covers "
              "what its PoCs and tests cover.",
        "es": "Aceptados por la versión del juez REGISTRADA EN ESTA CORRIDA (huella del juez: {rec}; el juez actual "
              "es {now}). El parche detuvo el mismo exploit y las pruebas funcionales pasaron; el juez solo cubre lo "
              "que cubren sus PoC y sus pruebas.",
    },
    "m_exported": {"en": "Exported", "es": "Exportados"},
    "m_exported_help": {"en": "Patches that were exported after the approval step of this run",
                        "es": "Parches que se exportaron después del paso de aprobación de esta corrida"},
    "m_cost": {"en": "Nemotron cost", "es": "Costo de Nemotron"},
    "m_cost_help": {"en": "Estimated from the token counts of this run's Nemotron calls",
                    "es": "Estimado a partir de los tokens de las llamadas a Nemotron de esta corrida"},
    "m_time": {"en": "Machine time", "es": "Tiempo de máquina"},
    "not_recorded": {"en": "not recorded", "es": "no registrado"},
    "run_caption": {
        "en": "Run `{file}` on {executor} with {model}. Top {top} entered verification.{legacy}",
        "es": "Corrida `{file}` en {executor} con {model}. Los {top} primeros pasaron a verificación.{legacy}",
    },
    "legacy": {
        "en": " This run predates the full inputs fingerprint; it is matched to the current ranking by identical "
              "finding ids, and its recorded ranks and scores equal the current ones.",
        "es": " Esta corrida es anterior a la huella completa de las entradas; se empareja con el orden actual por ids "
              "de hallazgo idénticos, y sus posiciones y puntajes registrados son iguales a los actuales.",
    },
    "judge_note": {
        "en": "**Judge version.** This run {what}. The path traversal check was strengthened afterwards to also "
              "catch an escape into a sibling directory whose name starts with `public` (a `startswith` comparison "
              "lets it through). Its patches were **not** re-judged inside this run, so read its path traversal "
              "verdict with that in mind. Judge recorded in this run: `{rec}`; current judge: `{now}`. A separate "
              "re-judge record, when present, is shown in the *Before / after* tab.",
        "es": "**Versión del juez.** Esta corrida {what}. La comprobación de path traversal se reforzó después para "
              "detectar también un escape a un directorio hermano cuyo nombre empieza con `public` (una comparación "
              "con `startswith` lo deja pasar). Sus parches **no** se volvieron a juzgar dentro de esta corrida, así "
              "que lee su veredicto de path traversal con eso en mente. Juez registrado en esta corrida: `{rec}`; "
              "juez actual: `{now}`. Un registro de re-juzgamiento aparte, cuando existe, se muestra en la pestaña "
              "*Antes / después*.",
    },
    "judge_what_missing": {"en": "did not record which version of the judge produced it",
                           "es": "no registró qué versión del juez la produjo"},
    "judge_what_other": {"en": "was judged with a different version of the PoCs and tests",
                         "es": "se juzgó con otra versión de los PoC y las pruebas"},
    "banner_human": {
        "en": "**Human approval.** A person was asked about each patch the judge accepted before export: "
              "{approved} of {total} were approved{unfinished}. Model-written code ran automatically, but only "
              "inside the sandbox.",
        "es": "**Aprobación humana.** Se le preguntó a una persona por cada parche que el juez aceptó antes de "
              "exportarlo: {approved} de {total} fueron aprobados{unfinished}. El código escrito por el modelo se "
              "ejecutó automáticamente, pero solo dentro del sandbox.",
    },
    "banner_unfinished": {"en": " ({e} exported, {p} pending, {f} failed)",
                          "es": " ({e} exportados, {p} pendientes, {f} fallidos)"},
    "banner_auto": {
        "en": "**Automatic approval (`--yes`).** This run does not show a person approving any patch; every "
              "question was skipped by the flag.",
        "es": "**Aprobación automática (`--yes`).** Esta corrida no muestra a ninguna persona aprobando un parche; "
              "la opción omitió todas las preguntas.",
    },
    "banner_none": {
        "en": "**No export decision.** The judge did not accept the patch, so no person was asked to approve "
              "anything and nothing was exported.",
        "es": "**Sin decisión de exportación.** El juez no aceptó el parche, así que no se le pidió a nadie aprobar "
              "nada y no se exportó nada.",
    },
    "banner_mixed": {"en": "**Mixed or unrecorded approval.** Check the `approval` field of each patch below.",
                     "es": "**Aprobación mixta o no registrada.** Revisa el campo `approval` de cada parche abajo."},
    # ---------- tabs ----------
    "tab_walk": {"en": "Walkthrough", "es": "Recorrido"},
    "tab_queue": {"en": "Priority queue", "es": "Cola de prioridad"},
    "tab_proof": {"en": "Before / after", "es": "Antes / después"},
    "tab_evidence": {"en": "Public evidence", "es": "Evidencia pública"},
    "tab_why": {"en": "Why this order", "es": "Por qué este orden"},
    "tab_repro": {"en": "Reproduce it", "es": "Reprodúcelo"},
    "tab_live": {"en": "Analyze (local)", "es": "Analizar (local)"},
    # ---------- walkthrough ----------
    "walk_none": {"en": "This run has no patched finding to follow. Pick another run in the sidebar.",
                  "es": "Esta corrida no tiene un hallazgo parcheado que seguir. Elige otra corrida en la barra lateral."},
    "walk_select": {"en": "Follow one finding through the loop", "es": "Sigue un hallazgo por el ciclo"},
    "the_poc": {"en": "the PoC", "es": "el PoC"},
    "cvss_code": {"en": "n/a (code finding)", "es": "n/a (hallazgo de código)"},
    "in_kev": {"en": "in", "es": "en"},
    "not_in_kev": {"en": "not in", "es": "no está en"},
    "internet_facing": {"en": "internet-facing", "es": "expuesto a internet"},
    "internal": {"en": "internal", "es": "interno"},
    "step1_h": {"en": "##### Step 1 · Prioritized by ScoreRisk (a rule, not a model)",
                "es": "##### Paso 1 · Priorizado por ScoreRisk (una regla, no un modelo)"},
    "step1_body": {
        "en": "ScoreRisk rank **#{rank} of {total}** (score {score}), band **{band}**: {basis}. Source: {source}. "
              "CVSS {cvss}; {kev} CISA KEV; asset {exposure} (declared).",
        "es": "Posición en ScoreRisk **#{rank} de {total}** (puntaje {score}), banda **{band}**: {basis}. "
              "Origen: {source}. CVSS {cvss}; {kev} CISA KEV; activo {exposure} (declarado).",
    },
    "step2_h": {"en": "##### Step 2 · Proven by execution: `{poc}` against the vulnerable app, in the sandbox",
                "es": "##### Paso 2 · Probado por ejecución: `{poc}` contra la app vulnerable, en el sandbox"},
    "verdict_caption": {"en": "Verdict: **{v}** (exit 1 means the exploit fired).",
                        "es": "Veredicto: **{v}** (exit 1 significa que el exploit funcionó)."},
    "step3_h": {"en": "##### Step 3 · Patched by Nemotron", "es": "##### Paso 3 · Parcheado por Nemotron"},
    "step3_via": {"en": "`{model}` through Nebius Token Factory. ", "es": "`{model}` a través de Nebius Token Factory. "},
    "step3_repaired": {
        "en": "Attempt 1 was rejected by the judge; its output went back to the model, which wrote attempt {n}. "
              "The *Before / after* tab shows the rejected attempt.",
        "es": "El juez rechazó el intento 1; su salida volvió al modelo, que escribió el intento {n}. "
              "La pestaña *Antes / después* muestra el intento rechazado.",
    },
    "step3_first": {"en": "Accepted at the first attempt.", "es": "Aceptado al primer intento."},
    "step4_h": {"en": "##### Step 4 · Re-tested with the same `{poc}` and the functional tests",
                "es": "##### Paso 4 · Re-probado con el mismo `{poc}` y las pruebas funcionales"},
    "step4_accepted": {"en": "Accepted: the PoC no longer fires (exit 0) and the functional tests pass (exit 0).",
                       "es": "Aceptado: el exploit ya no tiene efecto (exit 0) y las pruebas funcionales pasan (exit 0)."},
    "step4_rejected": {"en": "Rejected: PoC exit {pe}, tests exit {te}.",
                       "es": "Rechazado: PoC exit {pe}, pruebas exit {te}."},
    "step4_coverage": {"en": " The judge only covers what its PoC and tests cover.",
                       "es": " El juez solo cubre lo que cubren su PoC y sus pruebas."},
    "step4_older": {"en": " This run was judged by an older version of the judge (see the note at the top).",
                    "es": " Esta corrida la juzgó una versión anterior del juez (ver la nota de arriba)."},
    "step5_h": {"en": "##### Step 5 · Approval before export", "es": "##### Paso 5 · Aprobación antes de exportar"},
    "approval_field": {"en": "approval field", "es": "campo approval"},
    # ---------- priority queue ----------
    "where_internet": {"en": "internet-facing (declared)", "es": "expuesto a internet (declarado)"},
    "where_internal": {"en": "internal asset (declared)", "es": "activo interno (declarado)"},
    "describe": {"en": "EPSS {epss}, {kev} CISA KEV, {where}", "es": "EPSS {epss}, {kev} CISA KEV, {where}"},
    "queue_summary": {
        "en": "**The scanners produced {n} distinct findings ({cves} unique CVEs). {kev} {verb} in CISA KEV; "
              "{rare} have an EPSS below 0.05.**",
        "es": "**Los escáneres produjeron {n} hallazgos distintos ({cves} CVE únicos). {kev} {verb} en CISA KEV; "
              "{rare} tienen un EPSS menor que 0.05.**",
    },
    "verb_is": {"en": "is", "es": "está"},
    "verb_are": {"en": "are", "es": "están"},
    "looks_urgent": {
        "en": "**Looks urgent, is not.** {title} has CVSS {cvss} (#{crank} by severity) but ScoreRisk puts it at "
              "**#{rank}**: {desc}.",
        "es": "**Parece urgente, no lo es.** {title} tiene CVSS {cvss} (#{crank} por severidad), pero ScoreRisk lo "
              "pone en **#{rank}**: {desc}.",
    },
    "looks_minor": {
        "en": "**Looks minor, is not.** {title} has CVSS {cvss} (#{crank} by severity) but ScoreRisk puts it at "
              "**#{rank}**: {desc}.",
        "es": "**Parece menor, no lo es.** {title} tiene CVSS {cvss} (#{crank} por severidad), pero ScoreRisk lo "
              "pone en **#{rank}**: {desc}.",
    },
    "col_queue_help": {"en": "Position in the final queue", "es": "Posición en la cola final"},
    "col_finding": {"en": "Finding", "es": "Hallazgo"},
    "col_status": {"en": "Status", "es": "Estado"},
    "col_band": {"en": "Band", "es": "Banda"},
    "col_band_help": {"en": "Simplified, SSVC-inspired; basis in the full table",
                      "es": "Simplificada, inspirada en SSVC; el fundamento está en la tabla completa"},
    "col_kev_help": {"en": "Listed in CISA's Known Exploited Vulnerabilities catalog",
                     "es": "Incluido en el catálogo Known Exploited Vulnerabilities de CISA"},
    "col_basis": {"en": "Basis for the band", "es": "Fundamento de la banda"},
    "col_rank": {"en": "ScoreRisk rank", "es": "Posición ScoreRisk"},
    "col_cvss_rank": {"en": "CVSS rank", "es": "Posición CVSS"},
    "full_table": {"en": "Full table: finding ids, the basis of each band, and both ranks",
                   "es": "Tabla completa: ids de los hallazgos, el fundamento de cada banda y ambas posiciones"},
    "yes": {"en": "yes", "es": "sí"},
    "no": {"en": "no", "es": "no"},
    "queue_caption": {
        "en": "Confirmed findings jump to the top of the queue regardless of their pre-score. Findings without a "
              "PoC are ranked but reported as not verifiable, never as safe. Bands are a simplified mapping inspired "
              "by CISA's SSVC, not the official decision tree; asset exposure is declared in a fictional practice "
              "inventory.",
        "es": "Los hallazgos confirmados suben al principio de la cola, sin importar su puntaje previo. Los hallazgos "
              "sin PoC se ordenan, pero se reportan como no verificables, nunca como seguros. Las bandas son una "
              "correspondencia simplificada inspirada en el SSVC de CISA, no su árbol de decisión oficial; la "
              "exposición de los activos está declarada en un inventario de práctica ficticio.",
    },
    "axis_x": {"en": "CVSS base score (severity)", "es": "Puntaje base CVSS (severidad)"},
    "axis_y": {"en": "ScoreRisk (exploitability + exposure)", "es": "ScoreRisk (explotabilidad + exposición)"},
    "legend_kev": {"en": "in KEV", "es": "en KEV"},
    "legend_not_kev": {"en": "not in KEV", "es": "no está en KEV"},
    "tag_kev": {"en": " (in KEV)", "es": " (en KEV)"},
    "tt_title": {"en": "Title", "es": "Título"},
    "chart_caption": {
        "en": "Each dot is a finding. Severity alone (left to right) says little about urgency (bottom to top); "
              "most of the scanner's output sits low on the vertical axis. Labels show the findings discussed on "
              "this page with their ScoreRisk rank; hover any dot for its details.",
        "es": "Cada punto es un hallazgo. La severidad sola (de izquierda a derecha) dice poco sobre la urgencia "
              "(de abajo hacia arriba); la mayor parte de la salida del escáner queda abajo en el eje vertical. Las "
              "etiquetas muestran los hallazgos de los que habla esta página, con su posición en ScoreRisk; pasa el "
              "cursor sobre cualquier punto para ver su detalle.",
    },
    # ---------- before / after ----------
    "rejudge_title": {"en": "Re-judged with a later judge (a separate record, NOT part of this run)",
                      "es": "Re-juzgado con un juez posterior (un registro aparte, NO es parte de esta corrida)"},
    "rejudge_body": {
        "en": "`{name}` · judge `{fp}` ({matches}) · sandbox: Python {py}, Flask {fl}, pytest {pt}.  \n"
              "The patch stored in this run was rebuilt from its diff, applied to the current vulnerable app and "
              "judged again in the sandbox. This run itself was not modified, and nothing was exported.",
        "es": "`{name}` · juez `{fp}` ({matches}) · sandbox: Python {py}, Flask {fl}, pytest {pt}.  \n"
              "El parche guardado en esta corrida se reconstruyó desde su diff, se aplicó a la app vulnerable actual "
              "y se volvió a juzgar en el sandbox. Esta corrida no se modificó y no se exportó nada.",
    },
    "rejudge_matches": {"en": "matches the current judge", "es": "coincide con el juez actual"},
    "rejudge_older": {"en": "made with an older judge version than the current one",
                      "es": "hecho con una versión del juez anterior a la actual"},
    "rj_col_judge": {"en": "Judge in this run", "es": "Juez en esta corrida"},
    "rj_col_later": {"en": "Later judge", "es": "Juez posterior"},
    "rj_col_changed": {"en": "Changed", "es": "Cambió"},
    "rj_col_diff": {"en": "Diff rebuilt exactly", "es": "Diff reconstruido exacto"},
    "accepted": {"en": "accepted", "es": "aceptado"},
    "rejected": {"en": "rejected", "es": "rechazado"},
    "rejected_upper": {"en": "REJECTED", "es": "RECHAZADO"},
    "no_upper": {"en": "NO", "es": "NO"},
    "rejudge_output": {"en": "**{fid}**: output of the later judge ({poc}):",
                       "es": "**{fid}**: salida del juez posterior ({poc}):"},
    "no_patched": {"en": "No patched findings in this run.", "es": "No hay hallazgos parcheados en esta corrida."},
    "judge_line": {"en": "**Judge: {verdict}** · {export}  \n_{field}: {approval}{status}_",
                   "es": "**Juez: {verdict}** · {export}  \n_{field}: {approval}{status}_"},
    "verdict_accepted": {"en": "patch accepted (red to green)", "es": "parche aceptado (de rojo a verde)"},
    "verdict_not_accepted": {"en": "patch not accepted", "es": "parche no aceptado"},
    "attempt_rejected": {"en": "Attempt {n} was rejected by the judge, then Nemotron repaired it",
                         "es": "El juez rechazó el intento {n} y luego Nemotron lo reparó"},
    "attempt_body": {
        "en": "Same exploit, same tests. The judge's output was handed back to the model, which wrote the next "
              "attempt.",
        "es": "Mismo exploit, mismas pruebas. La salida del juez se le devolvió al modelo, que escribió el siguiente "
              "intento.",
    },
    "flipped_warning": {
        "en": "A later, stricter judge REJECTS this patch (see the re-judge record at the top of this tab). The "
              "'SAFE' output below is what the judge of this run saw.",
        "es": "Un juez posterior y más estricto RECHAZA este parche (ver el registro de re-juzgamiento al principio de "
              "esta pestaña). La salida 'SAFE' de abajo es lo que vio el juez de esta corrida.",
    },
    "before_h": {"en": "**Before: the exploit runs on the vulnerable app (sandbox)**",
                 "es": "**Antes: el exploit se ejecuta sobre la app vulnerable (sandbox)**"},
    "after_h": {"en": "**After: the same exploit and the functional tests on the patched app**",
                "es": "**Después: el mismo exploit y las pruebas funcionales sobre la app parcheada**"},
    "patch_expander": {"en": "Patch written by Nemotron (diff)", "es": "Parche escrito por Nemotron (diff)"},
    "download": {"en": "Download this patch (.diff)", "es": "Descargar este parche (.diff)"},
    # ---------- public evidence ----------
    "evidence_intro": {
        "en": "What execution cannot verify (no PoC for that class) is backed with **public evidence**: Tavily "
              "searches the web at runtime and Nemotron summarizes only what the sources support. This never "
              "changes the ScoreRisk number. Web results and summaries can differ between runs, which is exactly why "
              "this evidence is shown next to the score and never inside it.",
        "es": "Lo que la ejecución no puede verificar (no hay PoC para esa clase) se respalda con **evidencia "
              "pública**: Tavily busca en la web durante la corrida y Nemotron resume solo lo que las fuentes "
              "sostienen. Esto nunca cambia el número de ScoreRisk. Los resultados web y los resúmenes pueden cambiar "
              "entre corridas, y por eso esta evidencia se muestra junto al puntaje y nunca dentro de él.",
    },
    "evidence_recorded_note": {
        "en": "",
        "es": "Los resúmenes y las fuentes se muestran tal como quedaron registrados en la corrida, en inglés.",
    },
    "no_enrichment": {
        "en": "This run has no public-evidence step. Set TAVILY_API_KEY and run `python megapatch.py`.",
        "es": "Esta corrida no tiene el paso de evidencia pública. Configura TAVILY_API_KEY y ejecuta "
              "`python megapatch.py`.",
    },
    "skipped": {"en": "Skipped: {why}", "es": "Omitido: {why}"},
    "ev_exploited": {"en": "Exploited in the wild", "es": "Explotado activamente"},
    "ev_public_code": {"en": "Public exploit code", "es": "Código de exploit público"},
    "ev_vendor_fix": {"en": "Vendor fix available", "es": "Arreglo del proveedor disponible"},
    "ev_unclear": {"en": "not stated in sources", "es": "las fuentes no lo indican"},
    "no_sources": {"en": "No public sources found.", "es": "No se encontraron fuentes públicas."},
    "query": {"en": "Query: {q}", "es": "Consulta: {q}"},
    # ---------- why this order ----------
    "why_score": {
        "en": """
**ScoreRisk is a rule, not a model.** `100 x (0.50 E + 0.30 X + 0.20 S)`

| Signal | Weight | Source | Question it answers |
|---|---|---|---|
| E, exploitability | 50% | EPSS, CISA KEV (floor 0.90 when listed) | Can someone exploit it today? |
| X, exposure | 30% | Asset context: internet, authentication, production, sensitive data | If exploited, how reachable and how bad? |
| S, severity | 20% | CVSS base score | How bad is the bug in itself? |

CVSS weighs little on purpose: over-weighting it is exactly what creates the noise.
The same input always produces the same ranking, so the number is auditable.
""",
        "es": """
**ScoreRisk es una regla, no un modelo.** `100 x (0.50 E + 0.30 X + 0.20 S)`

| Señal | Peso | Fuente | Pregunta que responde |
|---|---|---|---|
| E, explotabilidad | 50% | EPSS, CISA KEV (mínimo 0.90 si está listado) | ¿Alguien puede explotarlo hoy? |
| X, exposición | 30% | Contexto del activo: internet, autenticación, producción, datos sensibles | Si se explota, ¿qué tan alcanzable y qué tan grave? |
| S, severidad | 20% | Puntaje base CVSS | ¿Qué tan grave es el error en sí? |

CVSS pesa poco a propósito: darle demasiado peso es justamente lo que crea el ruido.
La misma entrada siempre produce el mismo orden, así que el número es auditable.
""",
    },
    "why_bands": {
        "en": """
**Action bands** (names borrowed from CISA's SSVC: Act, Attend, Track\\*, Track). This is a **simplified,
project-specific rule table, not CISA's decision tree**:

| Band | Rule | Meaning |
|---|---|---|
| Act | Exploit confirmed in the sandbox, or in KEV and internet-facing | Handle first |
| Attend | In KEV but internal, or EPSS at or above {epss} | Handle sooner than the normal cycle |
| Track\\* | Internet-facing with no exploitation evidence | Watch closely |
| Track | No strong signal | Normal patch cycle |

The EPSS threshold ({epss}) is a project parameter, not an SSVC value. A band is only as
reliable as its inputs, and asset exposure is declared in a fictional practice inventory.
""",
        "es": """
**Bandas de acción** (nombres tomados del SSVC de CISA: Act, Attend, Track\\*, Track). Es una **tabla de reglas
simplificada y propia del proyecto, no el árbol de decisión de CISA**:

| Banda | Regla | Significado |
|---|---|---|
| Act | Exploit confirmado en el sandbox, o en KEV y expuesto a internet | Atender primero |
| Attend | En KEV pero interno, o EPSS igual o mayor que {epss} | Atender antes del ciclo normal |
| Track\\* | Expuesto a internet sin evidencia de explotación | Vigilar de cerca |
| Track | Sin señal fuerte | Ciclo normal de parches |

El umbral de EPSS ({epss}) es un parámetro del proyecto, no un valor del SSVC. Una banda solo es tan
confiable como sus entradas, y la exposición de los activos está declarada en un inventario de práctica ficticio.
""",
    },
    "why_snapshot": {
        "en": "**Data snapshot:** fetched {fetched}, CISA KEV catalog {version} ({total} entries). The findings are "
              "real scanner output (pip-audit over deliberately outdated pinned packages, Bandit over our practice "
              "app) and the CVE, EPSS, KEV and CVSS values are real. Which asset each finding belongs to and how "
              "exposed it is are declared assumptions of a fictional project, and the weights are starting points, "
              "not validated values.",
        "es": "**Instantánea de datos:** obtenida el {fetched}, catálogo CISA KEV {version} ({total} entradas). Los "
              "hallazgos son salida real de escáneres (pip-audit sobre paquetes fijados y desactualizados a "
              "propósito, Bandit sobre nuestra app de práctica) y los valores de CVE, EPSS, KEV y CVSS son reales. A "
              "qué activo pertenece cada hallazgo y cuán expuesto está son supuestos declarados de un proyecto "
              "ficticio, y los pesos son puntos de partida, no valores validados.",
    },
    "sens_title": {"en": "**Robustness check:** {n} weight/constant combinations",
                   "es": "**Prueba de robustez:** {n} combinaciones de pesos y constantes"},
    "sens_col_conclusion": {"en": "Conclusion", "es": "Conclusión"},
    "sens_col_holds": {"en": "Holds in", "es": "Se cumple en"},
    "sens_caption": {
        "en": "This varies the weights, not the inputs: the exposure of each asset is still an assumption.",
        "es": "Esto varía los pesos, no las entradas: la exposición de cada activo sigue siendo un supuesto.",
    },
    # ---------- reproduce ----------
    "repro_intro": {
        "en": "Verify the red to green claim yourself, with no API keys (the network is only needed to install the "
              "packages):",
        "es": "Comprueba por tu cuenta la afirmación de rojo a verde, sin claves de API (la red solo se necesita "
              "para instalar los paquetes):",
    },
    "repro_full": {"en": "Run the whole pipeline (needs Nebius Token Factory credentials and Sandboxes access):",
                   "es": "Ejecuta el pipeline completo (necesita credenciales de Nebius Token Factory y acceso a "
                         "Sandboxes):"},
    "repro_services": {
        "en": "**Runtime services:** NVIDIA Nemotron 3 Super through Nebius Token Factory writes the patches; "
              "Nebius Token Factory Sandboxes run every exploit, test and model-written patch in isolation. Live "
              "execution is not exposed in this public page, to protect the credits behind it.",
        "es": "**Servicios en ejecución:** NVIDIA Nemotron 3 Super, a través de Nebius Token Factory, escribe los "
              "parches; los Sandboxes de Nebius Token Factory ejecutan cada exploit, cada prueba y cada parche escrito "
              "por el modelo de forma aislada. La ejecución en vivo no está disponible en esta página pública, para "
              "proteger los créditos que la pagan.",
    },
    "isolation_title": {"en": "What the sandbox can see (observed, not promised)",
                        "es": "Qué puede ver el sandbox (observado, no prometido)"},
    "isolation_caption": {
        "en": "Recorded {date} by `isolation_check.py`, inside the same sandbox the judge uses. Network egress is "
              "not blocked and code runs as root inside the VM; isolation here means nothing sensitive is placed "
              "in it.",
        "es": "Registrado el {date} por `isolation_check.py`, dentro del mismo sandbox que usa el juez. La salida de "
              "red no está bloqueada y el código se ejecuta como root dentro de la VM; aislamiento aquí significa "
              "que no se pone nada sensible dentro.",
    },
    "empty": {"en": "(empty)", "es": "(vacío)"},
    # ---------- analyze (local) ----------
    "live_intro": {
        "en": "Run the loop on **one** finding from this page: confirm it with the exploit, let Nemotron write a "
              "patch, judge it with the **same** exploit and the tests, and decide whether to export it. Nothing is "
              "exported until you approve.",
        "es": "Ejecuta el ciclo sobre **un** hallazgo desde esta página: confírmalo con el exploit, deja que Nemotron "
              "escriba un parche, júzgalo con el **mismo** exploit y las pruebas, y decide si exportarlo. No se "
              "exporta nada hasta que lo apruebes.",
    },
    "live_independent": {
        "en": "This tab is independent of the recorded run selected in the sidebar: it makes a new analysis of one "
              "finding.",
        "es": "Esta pestaña es independiente de la corrida grabada elegida en la barra lateral: hace un análisis "
              "nuevo de un hallazgo.",
    },
    "live_trust": {
        "en": "Read this before trusting a result: the PoCs call the app in-process (Flask's test client), not over "
              "HTTP; the sandbox's outbound network is not blocked; and the judge only covers what its PoCs and "
              "tests cover, so 'accepted by the judge' does not mean 'safe in production'.",
        "es": "Lee esto antes de confiar en un resultado: los PoC llaman a la app en el mismo proceso (con el cliente "
              "de pruebas de Flask), no por HTTP; la red de salida del sandbox no está bloqueada; y el juez solo "
              "cubre lo que cubren sus PoC y sus pruebas, así que 'aceptado por el juez' no significa 'seguro en "
              "producción'.",
    },
    "live_off": {
        "en": "**Live runs are off here.** They spend model and sandbox credits, so they are a local opt-in: set "
              "`NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` and `MEGAPATCH_ENABLE_INTERACTIVE=1` in your own `.env` and "
              "run `streamlit run dashboard.py --server.address 127.0.0.1` on your machine. This public page only shows recorded runs.",
        "es": "**Las corridas en vivo están desactivadas aquí.** Gastan créditos del modelo y del sandbox, así que se "
              "activan solo en local: configura `NEBIUS_API_KEY`, `NEBIUS_PROJECT_ID` y "
              "`MEGAPATCH_ENABLE_INTERACTIVE=1` en tu propio `.env` y ejecuta `streamlit run dashboard.py --server.address 127.0.0.1` en tu "
              "máquina. Esta página pública solo muestra corridas grabadas.",
    },
    "live_select": {"en": "Finding to analyze", "es": "Hallazgo a analizar"},
    "live_judge_version": {"en": "Judge version used for this analysis: `{fp}`",
                           "es": "Versión del juez usada en este análisis: `{fp}`"},
    "live_run": {"en": "Run analysis in the sandbox", "es": "Ejecutar el análisis en el sandbox"},
    "live_in_progress": {"en": "Analysis in progress", "es": "Análisis en curso"},
    "live_done_awaiting": {"en": "Analysis finished: waiting for your decision",
                           "es": "Análisis terminado: esperando tu decisión"},
    "live_done_rejected": {"en": "Analysis finished: the judge did not accept the patch",
                           "es": "Análisis terminado: el juez no aceptó el parche"},
    "live_not_confirmed": {"en": "The exploit did not fire: nothing to fix",
                           "es": "El exploit no funcionó: no hay nada que arreglar"},
    "live_error": {"en": "The analysis stopped with an error", "es": "El análisis se detuvo con un error"},
    "live_progress": {"en": "**Progress**", "es": "**Progreso**"},
    "live_before": {"en": "**Before:** `{poc}` on the vulnerable app (exit {code})",
                    "es": "**Antes:** `{poc}` sobre la app vulnerable (exit {code})"},
    "live_after": {
        "en": "**After:** the same `{poc}` and the tests on the patched app (PoC exit {pe}, tests exit {te})",
        "es": "**Después:** el mismo `{poc}` y las pruebas sobre la app parcheada (PoC exit {pe}, pruebas exit {te})",
    },
    "live_exported": {"en": "Approved and exported: `{path}`. Record: `{record}`.",
                      "es": "Aprobado y exportado: `{path}`. Registro: `{record}`."},
    "live_not_exported": {"en": "Nothing was exported. Record: `{record}`.",
                          "es": "No se exportó nada. Registro: `{record}`."},
    "live_awaiting": {
        "en": "The judge accepted this patch, and **nothing has been exported**. Read the diff above; the export "
              "happens only if you approve it.",
        "es": "El juez aceptó este parche y **no se ha exportado nada**. Lee el diff de arriba; la exportación solo "
              "ocurre si la apruebas.",
    },
    "live_approve": {"en": "Approve export of this patch", "es": "Aprobar la exportación de este parche"},
    "live_reject": {"en": "Reject (export nothing)", "es": "Rechazar (no exportar nada)"},
    "live_no_patch": {"en": "There is no patch to approve. Nothing was exported.",
                      "es": "No hay un parche que aprobar. No se exportó nada."},
    "live_save_record": {"en": "Save a record of this analysis (exports nothing)",
                         "es": "Guardar un registro de este análisis (no exporta nada)"},
    "live_starting": {"en": "starting...", "es": "iniciando..."},
    "stage_running": {"en": "running", "es": "en curso"},
    "stage_done": {"en": "done", "es": "listo"},
    "stage_failed": {"en": "FAILED", "es": "FALLÓ"},
    "stage_pending": {"en": "waiting for you", "es": "esperando tu decisión"},
    "stage_prepare": {"en": "Prepare the sandbox (dependency checkpoint)",
                      "es": "Preparar el sandbox (punto de control de dependencias)"},
    "stage_confirm": {"en": "Run {poc} on the vulnerable app, in the sandbox",
                      "es": "Ejecutar {poc} sobre la app vulnerable, en el sandbox"},
    "stage_generate": {"en": "Ask Nemotron for a patch (attempt {n})", "es": "Pedir un parche a Nemotron (intento {n})"},
    "stage_judge": {"en": "Judge it in the sandbox: the same {poc} and the functional tests",
                    "es": "Juzgarlo en el sandbox: el mismo {poc} y las pruebas funcionales"},
    "stage_approval": {"en": "Waiting for a person to approve the export",
                       "es": "Esperando que una persona apruebe la exportación"},
    # ---------- statuses in the queue ----------
    "st_declined": {"en": "Judge accepted it; the person declined to export",
                    "es": "El juez lo aceptó; la persona rechazó exportarlo"},
    "st_pending": {"en": "Judge accepted it; the export was never confirmed (the session stopped before finishing)",
                   "es": "El juez lo aceptó; la exportación nunca se confirmó (la sesión se detuvo antes de terminar)"},
    "st_failed": {"en": "Judge accepted it; the export failed and was not recorded as exported",
                  "es": "El juez lo aceptó; la exportación falló y no quedó registrada como exportada"},
    "st_patched": {"en": "Confirmed, patched and re-tested", "es": "Confirmado, parcheado y re-probado"},
    "st_rejected": {"en": "Confirmed, patch rejected", "es": "Confirmado, parche rechazado"},
    "st_awaiting": {"en": "Confirmed, patch awaiting approval", "es": "Confirmado, parche a la espera de aprobación"},
    "st_not_verifiable": {"en": "Not verifiable (no PoC for this class)",
                          "es": "No verificable (no hay PoC para esta clase)"},
    "st_not_reproducible": {"en": "Not reproducible", "es": "No reproducible"},
    "st_outside_budget": {"en": "Ranked, outside verification budget", "es": "Ordenado, fuera del cupo de verificación"},
    # ---------- export states: English comes from evidence_utils.describe_export; these mirror it ----------
    "ex_not_accepted": {"en": "no export (the judge did not accept it)", "es": "sin exportación (el juez no lo aceptó)"},
    "ex_inconsistent": {"en": "the record is inconsistent (export_status={status}, exported={exported})", "es": "el registro es inconsistente (export_status={status}, exported={exported})"},
    "ex_unrecorded": {"en": "export approval not recorded", "es": "aprobación de exportación no registrada"},
    "ex_auto_exported": {"en": "exported automatically (--yes); no person approved it", "es": "exportado automáticamente (--yes); ninguna persona lo aprobó"},
    "ex_exported_human": {"en": "export approved by a person", "es": "exportación aprobada por una persona"},
    "ex_exported_other": {"en": "exported (export_status='exported')", "es": "exportado (export_status='exported')"},
    "ex_not_approved": {"en": "not exported: the person was asked and did not approve it (older record, no export_status)", "es": "no exportado: se le preguntó a la persona y no lo aprobó (registro antiguo, "
                                        "sin export_status)"},
    "ex_pending": {"en": "export pending: the person approved it, but the export was never confirmed (the session stopped before finishing; the diff may or may not exist)", "es": "exportación pendiente: la persona lo aprobó, pero la exportación nunca se confirmó "
                                   "(la sesión se detuvo antes de terminar; el diff puede existir o no)"},
    "ex_failed": {"en": "export failed: the diff could not be written", "es": "la exportación falló: no se pudo escribir el diff"},
    "ex_declined": {"en": "the person declined to export it", "es": "la persona rechazó exportarlo"},
    "ex_unknown": {"en": "export status not recognized: {status}", "es": "estado de exportación no reconocido: {status}"},
}

# Commands of the quick start: the same in both languages, exactly as in the README. None of them writes
# into the demo's scans/, data/ or evidence/ (check_walkthrough.py and check_repo_scan.py verify it).
QUICKSTART_COMMANDS = {
    "qs_install": "pip install -r requirements.txt\npip install -r requirements-scan.txt",
    "qs_scan": "streamlit run dashboard.py --server.address 127.0.0.1 -- --local-scan",
    "qs_rank": "python repo_scan.py PATH/TO/REPO\npython repo_scan.py --show PROJECT",
    "qs_analyze": "pip install -r requirements-pipeline.txt\npython megapatch.py --save-as my_run",
}
QUICKSTART_STEPS = ("qs_install", "qs_scan", "qs_assets", "qs_rank", "qs_analyze", "qs_results")

# Recorded labels that are data in the evidence files but read like interface text: shown translated,
# never changed in the files. Unknown values are shown exactly as recorded.
DATA_LABELS_ES = {
    # reasons recorded by repo_scan.py: requirement lines it does not audit, folders it leaves out
    "not pinned with ==": "no fijada con ==",
    "option line, not followed": "línea de opción, no se sigue",
    'version control': 'control de versiones',
    'environment folder (may hold secrets)': 'carpeta de entorno (puede contener secretos)',
    'virtual environment': 'entorno virtual',
    'build or cache folder': 'carpeta de compilación o caché',
    'environment file, never read': 'archivo de entorno, nunca se lee',
    'included file missing or outside the repository': 'archivo incluido inexistente o fuera del repositorio',
    # executors recorded in the runs
    "the Nebius sandbox": "el sandbox de Nebius",
    "THIS machine": "ESTA máquina",
    # scanner names from ingest.py
    "manual review": "revisión manual",
    # conclusions recorded in evidence/sensitivity.json
    "CVE-2023-37920 (CVSS 9.8, rarely exploited) ranks below CVE-2023-4863 (in KEV)":
        "CVE-2023-37920 (CVSS 9.8, rara vez explotado) queda por debajo de CVE-2023-4863 (en KEV)",
    "CVE-2023-37920 stays outside the top 20": "CVE-2023-37920 queda fuera de los 20 primeros",
    "CVE-2023-4863 (in KEV, internet-facing) stays in the top 3":
        "CVE-2023-4863 (en KEV, expuesto a internet) se mantiene entre los 3 primeros",
    "our 3 code findings all stay inside the top 8": "nuestros 3 hallazgos de código se mantienen entre los 8 primeros",
    # check names recorded in evidence/isolation_check.json
    "operating system": "sistema operativo",
    "running as": "usuario de ejecución",
    "environment variable NAMES (values are not recorded)":
        "NOMBRES de variables de entorno (los valores no se registran)",
    "variables that look like credentials": "variables que parecen credenciales",
    "files in the working directory": "archivos en el directorio de trabajo",
    "home directories": "directorios personales",
    "host drives or mounts from the developer's machine": "unidades o montajes de la máquina del desarrollador",
    "outbound TCP connection (pypi.org:443, the host pip uses)":
        "conexión TCP de salida (pypi.org:443, el host que usa pip)",
}

BASIS_ES = {
    "exploit confirmed in the sandbox (demo app)": "exploit confirmado en el sandbox (app de práctica)",
    "in CISA KEV + internet-facing (declared)": "en CISA KEV + expuesto a internet (declarado)",
    "in CISA KEV, internal asset (declared)": "en CISA KEV, activo interno (declarado)",
    "internet-facing (declared); no exploitation evidence": "expuesto a internet (declarado); sin evidencia de explotación",
    "no strong exploitation or exposure signal": "sin señal fuerte de explotación ni de exposición",
}
_EPSS_BASIS = re.compile(r"EPSS (\S+) is at or above (\S+); not in KEV")


def tr(lang, key, **values):
    """The text for `key` in `lang`, with its placeholders filled."""
    text = TEXT[key][lang]
    return text.format(**values) if values else text


def data_label(text, lang):
    """A recorded label shown in the interface language; unknown labels are shown as recorded."""
    return DATA_LABELS_ES.get(text, text) if lang == "es" else text


def band_basis(basis, lang):
    """The basis of an action band (bands.band_for) in the interface language."""
    if lang != "es":
        return basis
    if basis in BASIS_ES:
        return BASIS_ES[basis]
    match = _EPSS_BASIS.fullmatch(basis)
    if match:
        return f"EPSS {match.group(1)} igual o mayor que {match.group(2)}; no está en KEV"
    return basis


def status_label(raw, lang):
    """The status recorded in a run's final order, as a short label."""
    if "export not approved" in raw:  # historic wording said "verified in the sandbox"
        key = "st_declined"
    elif "export pending" in raw:
        key = "st_pending"
    elif "export FAILED" in raw:
        key = "st_failed"
    elif "PATCHED" in raw:
        key = "st_patched"
    elif "REJECTED" in raw:
        key = "st_rejected"
    elif "not run" in raw:
        key = "st_awaiting"
    elif raw == "NOT_VERIFIABLE":
        key = "st_not_verifiable"
    elif raw == "NOT_REPRODUCIBLE":
        key = "st_not_reproducible"
    elif raw.startswith("not verified (outside top N)"):
        key = "st_outside_budget"
    else:
        return raw
    return tr(lang, key)


def export_text(patch, lang):
    """What happened to a patch's export (evidence_utils.describe_export) in the interface language.
    The decision itself always comes from describe_export, so both languages say the same thing."""
    kind, text = describe_export(patch)
    if lang != "es":
        return text
    if kind == "exported":
        key = "ex_exported_human" if str(patch.get("approval", "")).startswith("human") else "ex_exported_other"
        return tr(lang, key)
    if kind == "failed":
        error = patch.get("export_error")
        return tr(lang, "ex_failed") + (f" (`{error}`)" if error else "")
    if kind == "inconsistent":
        return tr(lang, "ex_inconsistent", status=repr(patch.get("export_status")),
                  exported=bool(patch.get("exported")))
    if kind == "unknown":
        return tr(lang, "ex_unknown", status=repr(patch.get("export_status")))
    return tr(lang, f"ex_{kind}")


def stage_label(stage, poc, lang):
    """The label of an interactive-analysis stage, from its key (the engine records English labels)."""
    key = stage.get("key", "")
    if key == "prepare":
        return tr(lang, "stage_prepare")
    if key == "confirm":
        return tr(lang, "stage_confirm", poc=poc)
    if key.startswith("generate_"):
        return tr(lang, "stage_generate", n=key.split("_", 1)[1])
    if key.startswith("judge_"):
        return tr(lang, "stage_judge", poc=poc)
    if key == "approval":
        return tr(lang, "stage_approval")
    return stage.get("label", key)
