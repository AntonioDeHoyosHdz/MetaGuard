# Sesiones opacas de MetaGuard

La migración `0007_account_sessions` agrega una tabla separada por cuenta. Guarda únicamente los SHA-256 de un secreto aleatorio de sesión y de su token CSRF, junto con creación, vencimiento y revocación. La emisión exige una cuenta con email verificado; el helper recibe `now` y `expires_at` y deja commit/rollback al llamador. La revocación es una actualización condicional atómica.

El producto confirmó una cookie de sesión `HttpOnly` y `Secure` con defensa CSRF, sin guardar el token de sesión en almacenamiento del navegador. Los helpers de este módulo son privados: no configuran cookies, SameSite/dominio, políticas de expiración, recuperación ni MFA. El llamador debe terminar y verificar todos los factores de autenticación antes de pedir una sesión. No hay ruta pública de acceso, y la migración no se aplicó a PostgreSQL real en esta tarea.
