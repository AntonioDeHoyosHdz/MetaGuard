"""Render MetaGuard's Spanish account-verification email without transport dependencies."""

from html import escape

_TITLE = "Verifica tu correo"
VERIFICATION_SUBJECT = f"MetaGuard | {_TITLE}"

_INTRO = "Usa este código para confirmar la dirección de correo de tu cuenta MetaGuard."
_CODE_LABEL = "Código de verificación"
_LOCATION = "Tengo un código de verificación"
_ACTION = "Pega el código y selecciona «Verificar correo»."
_EXPIRY = "Este código es temporal y solo se puede usar una vez."
_UNREQUESTED = "Si no solicitaste una cuenta de MetaGuard, ignora este mensaje."
_PREVIEW = "Confirma la dirección de tu cuenta MetaGuard con un código de un solo uso."


def render_verification_text(token: str) -> str:
    """Render the plain-text alternative with the full code on its own line."""
    return (
        f"MetaGuard\n\n{_TITLE}\n\n{_INTRO}\n\n{_CODE_LABEL}:\n{token}\n\n"
        f"En MetaGuard, abre Cuenta y elige «{_LOCATION}». {_ACTION}\n\n{_EXPIRY}\n{_UNREQUESTED}\n"
    )


def render_verification_html(token: str) -> str:
    """Render the standalone HTML alternative using only the verification code."""
    return f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{VERIFICATION_SUBJECT}</title>
</head>
<body style="margin:0;background-color:#f5f2e9;color:#171714;font-family:Arial,sans-serif">
  <div aria-hidden="true" style="display:none;max-height:0;overflow:hidden;
    opacity:0;font-size:1px;line-height:1px;mso-hide:all">{_PREVIEW}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#f5f2e9">
    <tr><td align="center" style="padding:24px 10px 32px">
      <table role="presentation" align="center" width="100%" cellpadding="0" cellspacing="0"
        bgcolor="#fffdf5" style="max-width:560px;table-layout:fixed;border:2px solid #171714">
        <tr><td bgcolor="#171714" style="padding:15px 20px;border-bottom:4px solid #ffe600">
          <table role="presentation" cellpadding="0" cellspacing="0">
            <tr>
              <td width="36" height="36" align="center" valign="middle" bgcolor="#ffe600"
                aria-hidden="true" style="font-family:Consolas,monospace;
                font-size:15px;font-weight:bold;color:#171714">MG</td>
              <td style="padding-left:12px;color:#fffdf5;font-size:22px;
                font-weight:bold;letter-spacing:-.6px">MetaGuard</td>
            </tr>
          </table>
        </td></tr>
        <tr><td style="padding:23px 20px 20px">
          <h1 style="margin:0 0 6px;color:#171714;font-size:34px;line-height:1.12;
            letter-spacing:-1px">{_TITLE}</h1>
          <p style="margin:0 0 19px;color:#424239;font-size:16px;line-height:1.55">{_INTRO}</p>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" bgcolor="#ffe600"
            style="table-layout:fixed;border:2px solid #171714">
            <tr><td style="padding:10px 13px 0;color:#171714">
              <p style="margin:0;font-family:Consolas,monospace;font-size:12px;
                font-weight:bold;letter-spacing:.55px;text-transform:uppercase">{_CODE_LABEL}</p>
            </td></tr>
            <tr><td style="padding:7px 13px 13px">
              <code dir="ltr" style="display:block;padding:9px 10px;background-color:#fff9d1;
                border:1px solid #171714;color:#171714;font-family:Consolas,'Courier New',monospace;
                font-size:16px;line-height:1.45;word-break:break-all;overflow-wrap:anywhere"
              >{escape(token)}</code>
            </td></tr>
          </table>
          <p style="margin:10px 0 0;color:#424239;font-size:13px;line-height:1.5">{_EXPIRY}</p>
        </td></tr>
        <tr><td style="padding:0 20px 21px">
          <h2 style="margin:0 0 7px;color:#171714;font-size:18px">Dónde ingresar el código</h2>
          <ol style="margin:0;padding:0 0 0 23px;color:#34372e;font-size:15px;line-height:1.58">
            <li style="padding-left:3px;margin:0 0 3px">En MetaGuard, abre <strong>Cuenta</strong>
              y elige <strong>«{_LOCATION}»</strong>.</li>
            <li style="padding-left:3px">{_ACTION}</li>
          </ol>
        </td></tr>
        <tr><td bgcolor="#eeece1" style="padding:13px 20px;border-top:1px solid #cbc7b8">
          <p style="margin:0;color:#424239;font-size:13px;line-height:1.5">{_UNREQUESTED}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""
