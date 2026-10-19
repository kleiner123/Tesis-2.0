
# WebShield CORS & Supply Chain Auditor

MVP de una extensión Chrome Manifest V3 para un TFE de ciberseguridad.
Tema de Titulación
Kleiner Alarcón Cuenca
Ciberseguridad UNIR

## Funcionalidades actuales
- Solicita acceso únicamente al origen de la página actual.
- Audita recursos JavaScript cargados por la página.
- Identifica recursos de terceros.
- Comprueba presencia/ausencia de SRI (`integrity`).
- Observa cabeceras CORS de respuestas HTTP/HTTPS.
- Genera hallazgos básicos para configuraciones CORS.
- El modo protección queda deliberadamente desactivado como mitigación real en esta primera versión.

## Instalación local
1. Abrir `chrome://extensions/`.
2. Activar "Modo de desarrollador".
3. Seleccionar "Cargar descomprimida".
4. Elegir la carpeta `extension/`.
5. Abrir una página HTTP/HTTPS, pulsar WebShield y ejecutar "Auditar página actual".

## Siguiente iteración del TFE
- Motor de reglas CORS más completo.
- Identificación de librerías y versiones.
- Consulta de CVE desde una fuente definida por el proyecto.
- Política de allowlist para terceros.
- Mitigación mediante `declarativeNetRequest` con reglas explícitas y consentimiento del usuario.
- Exportación JSON/PDF.
- Dataset de casos seguros/inseguros para evaluación.
