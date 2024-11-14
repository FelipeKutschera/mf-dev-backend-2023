using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Net.Mail;
using System.Net;
using mf_dev_backend_2023.Models;

namespace mf_dev_backend_2023.Controllers
{
   // [Authorize(Roles = "Admin")]
    public class UsuariosController : Controller
    {
        private readonly AppDbContext _context;
        private readonly string _remetente;
        private readonly string _emailRemetente;
        private readonly string _senhaEmail;
        private readonly string _servidorSmtp;
        private readonly int _portaSmtp;

        public UsuariosController(AppDbContext context)
        {
            _context = context;
            // Configurações de envio de e-mail
            _remetente = "Suporte Event Pass";
            _emailRemetente = "luizeduardo0011@hotmail.com";
            _senhaEmail = "eventpass@2023";
            _servidorSmtp = "smtp-mail.outlook.com";
            _portaSmtp = 587;
        }

        // GET: Usuarios
        public async Task<IActionResult> Index()
        {
            return View(await _context.Usuarios.ToListAsync());
        }

        [AllowAnonymous]
        public IActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }

        private async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            using (var client = new SmtpClient(_servidorSmtp, _portaSmtp))
            {
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential(_emailRemetente, _senhaEmail);
                client.EnableSsl = true;

                var message = new MailMessage
                {
                    From = new MailAddress(_emailRemetente, _remetente),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                message.To.Add(toEmail);
                await client.SendMailAsync(message);
            }
        }

        [HttpPost]
       // [AllowAnonymous]
        public async Task<IActionResult> Login(Usuario usuario)
        {
            var dados = await _context.Usuarios
                .FirstOrDefaultAsync(u => u.Email == usuario.Email);

            if (dados == null || !BCrypt.Net.BCrypt.Verify(usuario.Senha, dados.Senha))
            {
                ViewBag.Message = "Usuário e/ou senha inválidos";
                return View();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, dados.Nome),
                new Claim(ClaimTypes.NameIdentifier, dados.Id.ToString()),
                new Claim(ClaimTypes.Role, dados.Perfil.ToString())
            };

            var usuarioIdentity = new ClaimsIdentity(claims, "login");
            ClaimsPrincipal principal = new ClaimsPrincipal(usuarioIdentity);

            var props = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTime.UtcNow.AddHours(8),
                IsPersistent = true,
            };

            await HttpContext.SignInAsync(principal, props);
            return Redirect("/");
        }

       // [AllowAnonymous]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Login", "Usuarios");
        }

        // GET: Usuarios/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == id);
            return usuario == null ? NotFound() : View(usuario);
        }

        // GET: Usuarios/Create
        public IActionResult Create() => View();

        [HttpPost]
      
        public async Task<IActionResult> Create([Bind("Id,Nome,Email,Senha,Perfil")] Usuario usuario)
        {
            if (ModelState.IsValid)
            {
                usuario.Senha = BCrypt.Net.BCrypt.HashPassword(usuario.Senha);
                _context.Add(usuario);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(usuario);
        }

        // GET: Usuarios/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FindAsync(id);
            return usuario == null ? NotFound() : View(usuario);
        }

        [HttpPost]
        
        public async Task<IActionResult> Edit(int id, [Bind("Id,Nome,Email,Senha,Perfil")] Usuario usuario)
        {
            if (id != usuario.Id) return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    usuario.Senha = BCrypt.Net.BCrypt.HashPassword(usuario.Senha);
                    _context.Update(usuario);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!_context.Usuarios.Any(e => e.Id == usuario.Id)) return NotFound();
                    throw;
                }
                return RedirectToAction(nameof(Index));
            }
            return View(usuario);
        }

        // GET: Usuarios/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(m => m.Id == id);
            return usuario == null ? NotFound() : View(usuario);
        }

        [HttpPost, ActionName("Delete")]
       // [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario != null) _context.Usuarios.Remove(usuario);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult EsqueciSenha()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> EsqueciSenha(string email)
        {
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Email == email);
            if (usuario == null)
            {
                ViewBag.Message = "E-mail não encontrado.";
                return View();
            }

            // Gerar Token de Redefinição
            usuario.TokenRedefinicaoSenha = Guid.NewGuid().ToString();
            usuario.TokenValidade = DateTime.UtcNow.AddHours(1);

            // Atualizar o usuário com o token
            _context.Update(usuario);
            await _context.SaveChangesAsync();

            // Link para redefinição de senha
            string callbackUrl = Url.Action("RedefinirSenha", "Usuarios", new { token = usuario.TokenRedefinicaoSenha }, Request.Scheme);
            string emailBody = $@"
        <h3>Redefinição de Senha</h3>
        <p>Clique no link abaixo para redefinir sua senha:</p>
        <a href='{callbackUrl}'>Redefinir Senha</a>";

            // Enviar Email
            await SendEmailAsync(usuario.Email, "Redefinição de Senha", emailBody);

            // Mensagem de sucesso
            ViewBag.Message = "Um link para redefinir sua senha foi enviado para o seu e-mail.";
            return View("ConfirmacaoEsqueciSenha");
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult RedefinirSenha(string token)
        {
            var usuario = _context.Usuarios.FirstOrDefault(u => u.TokenRedefinicaoSenha == token);
            if (usuario == null || usuario.TokenValidade < DateTime.UtcNow)
            {
                ViewBag.Message = "Token inválido ou expirado.";
                return View("EsqueciSenha");
            }

            ViewBag.Token = token;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> RedefinirSenha(string novaSenha, string token)
        {
            var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.TokenRedefinicaoSenha == token);

            if (usuario == null || usuario.TokenValidade < DateTime.UtcNow)
            {
                ViewBag.Message = "Token inválido ou expirado.";
                return View();
            }

            // Atualizar senha
            usuario.Senha = BCrypt.Net.BCrypt.HashPassword(novaSenha);
            usuario.TokenRedefinicaoSenha = null;
            usuario.TokenValidade = null;

            _context.Update(usuario);
            await _context.SaveChangesAsync();

            ViewBag.Message = "Senha redefinida com sucesso.";
            return RedirectToAction("Login");
        }


    }
}
