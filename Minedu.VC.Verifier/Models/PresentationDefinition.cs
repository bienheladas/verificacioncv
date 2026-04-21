using System.Data;

namespace Minedu.VC.Verifier.Models
{
    public class PresentationDefinition
    {
        public string Id { get; set; } = default!;
        public string Name { get; set; } = default!;
        public string Purpose { get; set; } = default!;
        public List<InputDescriptor> InputDescriptors { get; set; } = new();
    }

    public class InputDescriptor
    {
        public string Id { get; set; } = default!;
        public string Name { get; set; } = default!;
        public string Purpose { get; set; } = default!;
        public List<Constraint> Constraints { get; set; } = new();
    }

    public class Constraint
    {
        public string Path { get; set; } = default!;
        public string Filter { get; set; } = default!;
    }
}
