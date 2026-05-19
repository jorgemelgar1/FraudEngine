# Cubo Fraud Engine — Guía de instalación

Esta es la app de escritorio del Fraud Engine para Windows. A diferencia de
la versión web, no tiene límites de tamaño y procesa CSVs locales rápido.

## Cómo instalarla

### 1. Descarga el instalador

Abre este enlace y descarga el archivo `.exe` más reciente:

<https://github.com/jorgemelgar1/FraudEngine/releases/latest>

Busca el archivo que se llama algo como:

```
Cubo.Fraud.Engine_0.1.0_x64-setup.exe
```

(El número de versión irá subiendo con cada actualización.)

### 2. Acepta la advertencia de Windows ⚠️

Al hacer doble-clic en el `.exe` descargado, Windows mostrará una pantalla
azul que dice:

> **Windows protegió tu PC**
> Microsoft Defender SmartScreen impidió el inicio de una aplicación no
> reconocida...

**Esto es normal y esperado.** Windows muestra esta advertencia para
cualquier app que no esté firmada con un certificado pagado de Microsoft.
La app es de Cubo Pago y es segura — sólo no compramos el certificado
(que cuesta cientos de dólares al año y no aporta nada técnico).

Para continuar:

1. Haz clic en el enlace pequeño que dice **"Más información"** (está cerca
   del centro de la pantalla, en letras chiquitas).
2. Aparecerá un botón nuevo: **"Ejecutar de todas formas"**. Haz clic ahí.
3. El instalador se abrirá normalmente — sigue Siguiente → Siguiente →
   Instalar.

**Esto solo ocurre la primera vez.** Las actualizaciones futuras se aplican
automáticamente sin volver a mostrar esta advertencia.

### 3. Inicia sesión

1. Abre **Cubo Fraud Engine** desde el menú Inicio (busca por nombre o
   verás el ícono de Cubo Holmes).
2. Haz clic en **"Iniciar sesión con Google"**.
3. Se abrirá tu navegador. Elige tu cuenta `@cubopago.com`.
4. Después de elegir la cuenta, vuelve a la app de escritorio —
   automáticamente entrarás a la pantalla principal.

Si tu navegador muestra "¿Permitir que este sitio abra Cubo Fraud Engine?",
acepta. Solo se pregunta la primera vez.

## Cómo usarla

- **Analizar:** arrastra un CSV (de cualquier tamaño) a la ventana o haz
  clic para examinarlo. El análisis corre localmente en tu PC y los
  resultados se sincronizan con Supabase como siempre.
- **Pendientes:** revisa los hallazgos críticos pendientes — Aceptar
  agrega el merchant a la watchlist, Descartar lo deja como falso positivo.
- **Historial:** consulta decisiones anteriores. Tienes 24 horas para
  deshacer una decisión.

## Modo sin conexión

Si pierdes internet:
- Los análisis siguen funcionando (con la watchlist en caché).
- Los resultados se ponen en cola local.
- Cuando vuelvas a estar en línea, la cola se sincroniza sola.

## Actualizaciones

La app se conecta a GitHub al iniciar y revisa si hay versión nueva. Si
hay, aparece un mensaje verde arriba que dice "Actualización disponible".
Hacer clic descarga y aplica la actualización en segundos — sin volver a
mostrar SmartScreen.

## Si algo no funciona

Escribe a Jorge Melgar (`jmelgar@cubopago.com`) con una captura de pantalla
del error y el archivo CSV que estabas intentando procesar (si aplica).

---

**Versión web (Vercel):** sigue disponible en
<https://fraud-engine.vercel.app>. Tiene los mismos datos. Úsala desde
cualquier navegador si no puedes instalar la app de escritorio.
