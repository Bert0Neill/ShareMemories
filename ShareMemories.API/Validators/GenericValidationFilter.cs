namespace ShareMemories.API.Validators
{
    using FluentValidation;
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;

    public class GenericValidationFilter<TValidator, TModel> : IEndpointFilter
        where TValidator : IValidator<TModel>
    {
        private readonly TValidator _validator;

        public GenericValidationFilter(TValidator validator)
        {
            _validator = validator;
        }

        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            var model = context.Arguments.OfType<TModel>().FirstOrDefault();

            if (model == null)
            {
                return Results.BadRequest("Invalid model.");
            }

            var validationResult = await _validator.ValidateAsync(model);

            if (!validationResult.IsValid)
            {
                return Results.BadRequest(validationResult.Errors);
            }

            return await next(context);
        }
    }

}
