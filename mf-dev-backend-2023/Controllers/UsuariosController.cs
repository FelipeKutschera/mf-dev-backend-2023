using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using mf_dev_backend_2023.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace mf_dev_backend_2023.Controllers
{
    [Authorize(Roles ="Admin")]
    public class UsuariosController : Controller
    {
        private readonly AppDbContext _context;

        public UsuariosController(AppDbContext context)
        {
            _context = context;
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


        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(Usuario usuario)
        {
            var dados = await _context.Usuarios
                .FindAsync(usuario.Id);

            if(dados == null)
            {
                ViewBag.Message = "Usuario e/ou senha invalidos";
                return View();
            }

            bool senhaok = BCrypt.Net.BCrypt.Verify(usuario.Senha, dados.Senha);

            if (senhaok)
            {
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
                    ExpiresUtc = DateTime.UtcNow.ToLocalTime().AddHours(8),
                    IsPersistent = true,
                };

                await HttpContext.SignInAsync(principal, props);

               return Redirect("/");

            } 
            else
            {
                ViewBag.Message = "Usuario e/ou senha invalidos";

            }
            

            return View();
        }

        [AllowAnonymous]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Login", "Usuarios");
        }

        // GET: Usuarios/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var usuario = await _context.Usuarios
                .FirstOrDefaultAsync(m => m.Id == id);
            if (usuario == null)
            {
                return NotFound();
            }

            return View(usuario);
        }

        // GET: Usuarios/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Usuarios/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Nome,Senha,Perfil")] Usuario usuario)
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
            if (id == null)
            {
                return NotFound();
            }

            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario == null)
            {
                return NotFound();
            }
            return View(usuario);
        }

        // POST: Usuarios/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Nome,Senha,Perfil")] Usuario usuario)
        {
            if (id != usuario.Id)
            {
                return NotFound();
            }

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
                    if (!UsuarioExists(usuario.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(usuario);
        }

        // GET: Usuarios/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var usuario = await _context.Usuarios
                .FirstOrDefaultAsync(m => m.Id == id);
            if (usuario == null)
            {
                return NotFound();
            }

            return View(usuario);
        }

        // POST: Usuarios/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var usuario = await _context.Usuarios.FindAsync(id);
            if (usuario != null)
            {
                _context.Usuarios.Remove(usuario);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool UsuarioExists(int id)
        {
            return _context.Usuarios.Any(e => e.Id == id);
        }
         
[HttpPost]
public async Task<IActionResult> EsqueciSenha(string email)
{
    var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Email == email);

    if (usuario == null)
    {
        ViewBag.Message = "E-mail não encontrado.";
        return View();
    }

    // Gerar um token e definir validade de 1 hora
    string token = Guid.NewGuid().ToString();
    usuario.TokenRedefinicaoSenha = token;
    usuario.TokenValidade = DateTime.UtcNow.AddHours(1);

    _context.Update(usuario);
    await _context.SaveChangesAsync();

    string callbackUrl = Url.Action("RedefinirSenha", "Usuarios", new { token = token }, Request.Scheme);

    // Envie um e-mail ao usuário com um link para redefinir a senha
    await SendEmailAsync(usuario.Email, "Redefinição de Senha",
        $"Clique no link abaixo para redefinir sua senha:\n\n {callbackUrl}");

    ViewBag.Message = "Um link para redefinir sua senha foi enviado para o seu e-mail.";
    return View();
}

public IActionResult RedefinirSenha(string token)
{
    var usuario = _context.Usuarios.FirstOrDefault(u => u.TokenRedefinicaoSenha == token);

    // Verificar se o token existe e se ainda está válido
    if (usuario == null || usuario.TokenValidade < DateTime.UtcNow)
    {
        ViewBag.Message = "Token de redefinição de senha inválido ou expirado.";
        return View("EsqueciSenha");
    }

    ViewBag.Token = token;
    return View();
}


       [HttpPost]
public async Task<IActionResult> RedefinirSenha(string novaSenha, string token)
{
    var usuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.TokenRedefinicaoSenha == token);

    if (usuario == null || usuario.TokenValidade < DateTime.UtcNow)
    {
        ViewBag.Message = "Token de redefinição de senha inválido ou expirado.";
        return View();
    }

    // Verificar se a nova senha atende aos requisitos de complexidade
    if (string.IsNullOrWhiteSpace(novaSenha) || novaSenha.Length < 8)
    {
        ViewBag.Message = "A nova senha deve ter pelo menos 8 caracteres.";
        return View();
    }

    // Atualizar a senha do usuário e limpar o token
    usuario.Senha = BCrypt.Net.BCrypt.HashPassword(novaSenha);
    usuario.TokenRedefinicaoSenha = null;
    usuario.TokenValidade = null;

    _context.Update(usuario);
    await _context.SaveChangesAsync();

    ViewBag.Message = "Senha redefinida com sucesso. Agora você pode fazer login com a nova senha.";
    return RedirectToAction("Login", "Usuarios");
}

}
