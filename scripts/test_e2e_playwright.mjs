import { chromium } from 'playwright';
import { execSync } from 'child_process';
import path from 'path';

const BASE_URL = 'https://metaguard.duckdns.org';
const PEM_PATH = 'C:/Users/jaras/Downloads/meta-guard.pem';
const BACKEND_HOST = '54.197.251.32';

function getEmailCode(targetEmail, type = 'verify') {
  console.log(`[IMAP] Buscando codigo (${type}) para ${targetEmail}...`);
  const cmd = `ssh -n -i "${PEM_PATH}" ubuntu@${BACKEND_HOST} "sudo python3 /opt/metaguard-registration-preview/fetch_code.py ${targetEmail} ${type}"`;
  const out = execSync(cmd, { encoding: 'utf-8', timeout: 35000 });
  const match = out.match(/CODE:([A-Za-z0-9_-]+)/);
  if (!match || match[1] === 'NONE') {
    throw new Error(`No se pudo obtener el codigo ${type} para ${targetEmail}. Salida: ${out}`);
  }
  console.log(`[IMAP] Codigo obtenido: ${match[1]}`);
  return match[1];
}

async function runE2EForAccount(browser, email, password, newPassword) {
  console.log(`\n======================================================`);
  console.log(`=== INICIANDO E2E PARA CUENTA: ${email} ===`);
  console.log(`======================================================`);

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  // 1. Ir a la home
  console.log(`1. Navegando a ${BASE_URL}...`);
  await page.goto(`${BASE_URL}/#cuenta`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);

  // 2. Registro: cambiar a vista Crear una cuenta si no está
  console.log('2. Pasando a formulario de registro...');
  const createAccountBtn = page.locator('button:has-text("Crear una cuenta")');
  if (await createAccountBtn.isVisible()) {
    await createAccountBtn.click();
  }

  console.log('Llenando formulario de registro...');
  await page.fill('#register-email', email);
  await page.fill('#register-password', password);
  await page.click('button[type="submit"]:has-text("Crear cuenta")');

  // Esperar a que pase a la vista de verificación
  console.log('Esperando vista de verificacion...');
  await page.waitForSelector('#verify-token', { timeout: 15000 });

  // 3. Obtener token por IMAP
  const verifyToken = getEmailCode(email, 'verify');

  // 4. Ingresar token y verificar correo
  console.log('Ingresando token de verificacion...');
  await page.fill('#verify-token', verifyToken);
  await page.click('button[type="submit"]:has-text("Verificar correo")');

  // 5. Esperar confirmacion y vista de inicio de sesion
  console.log('Esperando confirmacion de verificacion e inicio de sesion...');
  await page.waitForSelector('#login-password', { timeout: 15000 });
  console.log('Vista de inicio de sesion cargada.');

  // 6. Probar contrasena mala rechazada
  console.log('6. Probando contrasena incorrecta...');
  await page.fill('#login-email', email);
  await page.fill('#login-password', 'ClaveTotalmenteErronea123!@#');
  await page.click('button[type="submit"]:has-text("Iniciar sesión")');

  // Verificar mensaje de error
  await page.waitForSelector('.auth-error, p[role="alert"]', { timeout: 10000 });
  const errorText = await page.locator('.auth-error, p[role="alert"]').innerText();
  console.log(`[PASS] Error mostrado con clave incorrecta: "${errorText}"`);

  // 7. Iniciar sesion con contrasena correcta
  console.log('7. Iniciando sesion con credenciales correctas...');
  await page.fill('#login-email', email);
  await page.fill('#login-password', password);
  await page.click('button[type="submit"]:has-text("Iniciar sesión")');

  // Esperar que la sesion inicie
  await page.waitForSelector('button:has-text("Cerrar sesión")', { timeout: 15000 });
  console.log('[PASS] Sesion iniciada correctamente. Estado autenticado.');

  // 8. Navegar a archivos y subir imagen
  console.log('8. Navegando a seccion de archivos...');
  await page.goto(`${BASE_URL}/#demostracion`, { waitUntil: 'networkidle' });
  await page.waitForSelector('#analysis-file', { timeout: 15000 });

  const jpgPath = path.resolve('test_fixtures/sample.jpg');
  console.log(`Subiendo imagen: ${jpgPath}...`);
  await page.setInputFiles('#analysis-file', jpgPath);
  await page.click('button[type="submit"]:has-text("Subir y analizar")');

  // Esperar que el analisis termine
  console.log('Esperando resultado de analisis de imagen...');
  await page.waitForSelector('.file-status:has-text("Tu reporte está listo")', { timeout: 20000 });
  console.log('[PASS] Analisis de imagen completado con reporte listo.');

  // 9. Subir archivo PDF
  const pdfPath = path.resolve('test_fixtures/sample.pdf');
  console.log(`Subiendo PDF: ${pdfPath}...`);
  await page.setInputFiles('#analysis-file', pdfPath);
  await page.click('button[type="submit"]:has-text("Subir y analizar")');

  console.log('Esperando resultado de analisis de PDF...');
  await page.waitForSelector('strong:has-text("Reporte de archivo PDF")', { timeout: 30000 });
  console.log('[PASS] Analisis de PDF completado con reporte listo.');

  // 10. Cerrar sesion
  console.log('10. Cerrando sesion...');
  await page.goto(`${BASE_URL}/#cuenta`, { waitUntil: 'networkidle' });
  await page.click('button:has-text("Cerrar sesión")');
  await page.waitForSelector('#login-email', { timeout: 10000 });
  console.log('[PASS] Sesion cerrada.');

  // 11. Recuperar contrasena
  console.log('11. Iniciando flujo de recuperacion de contrasena...');
  await page.click('button:has-text("Olvidé mi contraseña")');
  await page.waitForSelector('#reset-email', { timeout: 10000 });

  console.log('Solicitando codigo de recuperacion...');
  await page.fill('#reset-email', email);
  await page.click('button[type="submit"]:has-text("Pedir código de recuperación")');

  // Esperar que pida el codigo
  await page.waitForSelector('#reset-code', { timeout: 15000 });

  // Obtener codigo de reset por IMAP
  const resetCode = getEmailCode(email, 'reset');

  console.log('Ingresando codigo de restablecimiento y nueva contrasena...');
  await page.fill('#reset-code', resetCode);
  await page.fill('#reset-password', newPassword);
  await page.fill('#reset-confirmation', newPassword);
  await page.click('button[type="submit"]:has-text("Restablecer contraseña")');

  // Esperar confirmacion
  console.log('Esperando confirmacion de restablecimiento...');
  await page.waitForSelector('#login-password', { timeout: 15000 });
  console.log('[PASS] Contrasena restablecida.');

  // Iniciar sesion con la NUEVA contrasena
  console.log('Iniciando sesion con la NUEVA contrasena...');
  await page.fill('#login-email', email);
  await page.fill('#login-password', newPassword);
  await page.click('button[type="submit"]:has-text("Iniciar sesión")');

  await page.waitForSelector('button:has-text("Cerrar sesión")', { timeout: 15000 });
  console.log('[PASS] Inicio de sesion exitoso con la nueva contrasena.');

  await context.close();
  console.log(`=== CUENTA ${email} COMPLETADA EXITOSAMENTE ===\n`);
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    executablePath: 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  });

  try {
    // Cuenta 1
    await runE2EForAccount(
      browser,
      'jarassanchezl+prueba1@gmail.com',
      'MetaGuard2026!Prueba1',
      'MetaGuard2026!Nueva1'
    );

    // Cuenta 2
    await runE2EForAccount(
      browser,
      'jarassanchezl+prueba2@gmail.com',
      'MetaGuard2026!Prueba2',
      'MetaGuard2026!Nueva2'
    );

    console.log('\n>>> TODAS LAS PRUEBAS E2E PASARON CON EXITO TOTAL <<<');
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error('\n[ERROR E2E]:', err);
  process.exit(1);
});
