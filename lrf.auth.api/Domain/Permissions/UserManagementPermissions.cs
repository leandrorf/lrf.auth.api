namespace lrf.auth.api.Domain.Permissions;

/// <summary>
/// Permissões para o cadastro de usuários (CRUD). Nomes estáveis no token (claim <c>permission</c>).
/// </summary>
public static class UserManagementPermissions
{
    /// <summary>Leitura (listar/consultar usuários).</summary>
    public const string Read = "users.read";

    /// <summary>Escrita no sentido de inclusão / cadastro de novo usuário.</summary>
    public const string Create = "users.create";

    /// <summary>Atualização de dados de usuário existente.</summary>
    public const string Update = "users.update";

    /// <summary>Remoção (exclusão lógica ou física, conforme regra de negócio).</summary>
    public const string Delete = "users.delete";

    public static readonly IReadOnlyList<string> All = new[] { Read, Create, Update, Delete };
}
