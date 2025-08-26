using SkiaSharp;
using System.Reflection;

namespace AuthCenter.Utils
{
    public class CaptchaUtils
    {
        // Remove O to avoid 0O
        private const string Letters = "1,2,3,4,5,6,7,8,9,a,b,c,d,e,f,g,h,i,j,k,l,m,n,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,P,Q,R,S,T,U,V,W,X,Y,Z";
        private const string Numbers = "0,1,2,3,4,5,6,7,8,9";
        private const string Alphabet = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,J,K,L,M,N,P,Q,R,S,T,U,V,W,X,Y,Z";
        private static List<SKColor> Colors = [
            SKColor.Parse("#0087ff"),
            SKColor.Parse("#339933"),
            SKColor.Parse("#ff6666"),
            SKColor.Parse("#ff9900"),
            SKColor.Parse("#996600"),
            SKColor.Parse("#996699"),
            SKColor.Parse("#339999"),
            SKColor.Parse("#6666ff"),
            SKColor.Parse("#0066cc"),
            SKColor.Parse("#cc3333"),
            SKColor.Parse("#0099cc"),
            SKColor.Parse("#003366")
        ];
        private static SKTypeface DefaultFont;

        static CaptchaUtils()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var names = assembly.GetManifestResourceNames();
            var actionjFont = assembly.GetManifestResourceStream("AuthCenter.Assets.actionj.ttf");
            DefaultFont = SKTypeface.FromStream(actionjFont);
        }

        public static (string, string) GenerateCodeStr(int codeLen, string codeType)
        {
            Random random = new Random();
            if (codeType == "Calculate")
            {
                int num1 = random.Next(50);
                int num2 = random.Next(50);
                int oper = random.Next(0, 2);

                if (num1 < num2)
                {
                    (num1, num2) = (num2, num1);
                }

                return oper switch
                {
                    0 => (num1.ToString() + "+" + num2.ToString(), (num1 + num2).ToString()),
                    1 => (num1.ToString() + "-" + num2.ToString(), (num1 - num2).ToString()),
                    2 => (num1.ToString() + "×" + num2.ToString(), (num1 * num2).ToString()),
                    _ => (num1.ToString() + "+" + num2.ToString(), (num1 + num2).ToString()),
                };
            }
            else
            {
                var codeArray = Letters.Split(',').ToArray();
                if (codeType == "Number")
                {
                    codeArray = Numbers.Split(',').ToArray();
                }
                else if (codeType == "Alphabet")
                {
                    codeArray = Alphabet.Split(',').ToArray();
                }

                Random.Shared.Shuffle(codeArray ?? Array.Empty<string>());
                var finalStr = "";
                for (int i = 0; i < codeLen; i++)
                {
                    finalStr += codeArray?[i];
                }

                return (finalStr, finalStr);
            }
        }

        public static string GenerateBase64Captcha(string captchaCode, float fontSize, int maxPy, int height = 65)
        {
            Random random = new Random();

            var width = (int)(fontSize * (captchaCode.Length + 1));

            using var surface = SKSurface.Create(new SKImageInfo(width, height));
            var canvas = surface.Canvas;
            canvas.Clear(SKColors.White);
            canvas.Translate(width / 2, height / 2);

            for (int i = 0; i < captchaCode.Length; i++)
            {
                double px = -captchaCode.Length / 2.0 * fontSize + fontSize * i;
                var coord = new SKPoint((int)px, maxPy);
                var paint = new SKPaint()
                {
                    Color = Colors[random.Next(11)],
                    IsAntialias = true,
                    Style = SKPaintStyle.Fill,
                };
                SKFont skFont = new SKFont();
                skFont.Size = fontSize;
                skFont.ScaleX = (float)random.NextDouble() + 1;
                skFont.Typeface = DefaultFont;

                float rr = (float)(random.NextDouble() / 2 - 0.25);
                canvas.RotateRadians(rr);
                canvas.DrawText(captchaCode[i].ToString(), coord, SKTextAlign.Center, skFont, paint);
                canvas.RotateRadians(-rr);
            }
            for (int i = 0; i < width * height / 500; i++)
            {
                var point1 = new SKPoint(random.Next(width) - width / 2, random.Next(height) - height / 2);
                var point2 = new SKPoint(random.Next(width) - width / 2, random.Next(height) - height / 2);
                var paint = new SKPaint()
                {
                    Color = new SKColor((byte)random.Next(255), (byte)random.Next(255), (byte)random.Next(255), 126),
                    IsAntialias = true,
                    Style = SKPaintStyle.Fill,
                };
                canvas.DrawLine(point1, point2, paint);
            }

            using var image = surface.Snapshot();
            using var ms = new MemoryStream();
            image.Encode(SKEncodedImageFormat.Png, 80).SaveTo(ms);
            byte[] imageBytes = ms.ToArray();
            string base64String = Convert.ToBase64String(imageBytes);

            return base64String;
        }
    }
}
