using System.Collections;

namespace AuthCenter.ViewModels
{
    public class JSONResult
    {
        public int code { get; set; }
        public Object? data { get; set; }
        public string? message { get; set; }

        public static JSONResult ResponseOk(Object data, string message = "成功")
        {
            return new JSONResult
            {
                code = 0,
                data = data,
                message = message,
            };
        }

        public static JSONResult ResponseOk(string message = "成功")
        {
            return new JSONResult
            {
                code = 0,
                data = null,
                message = message,
            };
        }

        public static JSONResult ResponseList(IList list, int total, string message = "成功")
        {
            return new JSONResult
            {
                code = 0,
                data = new
                {
                    items = list,
                    total,
                },
                message = message,
            };
        }

        public static JSONResult ResponseError(string message, int code = -1)
        {
            return new JSONResult
            {
                code = code,
                message = message,
            };
        }
    }
}
