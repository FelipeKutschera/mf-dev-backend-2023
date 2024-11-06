using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace mf_dev_backend_2023.Models
{
    [Table("Consumos")]
    public class Consumo
    {
        [Key]
        public int Id { get; set; }

        [Required(ErrorMessage = "Obrigatorio informar a descrição")]
        [Display(Name = "Descrição")]
        public string Descricao { get; set; }

        [Required(ErrorMessage = "Obrigatorio informar a data")]
        public DateTime Date { get; set; }

        [Required(ErrorMessage = "Obrigatorio informar o valor")]
        public decimal valor { get; set; }

        [Required(ErrorMessage = "Obrigatorio informar a quilometragem")]
        public int km { get; set; }

        [Display(Name = "Tipo de Combustivel")]
        public TipoCombustivel Tipo { get; set; }

        [Display(Name = "veiculo")]
        public int VeiculoId { get; set; }

        [ForeignKey("VeiculoId")]
        public Veiculo veiculo { get; set; }

        //public ICollection<Veiculo> Veiculos { get; set; }


    }

    public enum TipoCombustivel
    {
        Gasolina,
        Etanol
    }

}