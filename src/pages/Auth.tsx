import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { useAuth } from '@/hooks/useAuth';
import { useToast } from '@/hooks/use-toast';

const Auth = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [useDemoCredentials, setUseDemoCredentials] = useState(false);

  const { signIn } = useAuth();
  const { toast } = useToast();
  const navigate = useNavigate();

  const handleDemoToggle = (checked: boolean | string) => {
    const isChecked = checked === true;
    setUseDemoCredentials(isChecked);
    if (isChecked) {
      setLoginEmail('analyst@hawkeye.com');
      setLoginPassword('demo123456');
    } else {
      setLoginEmail('');
      setLoginPassword('');
    }
  };

  const handleSignIn = (e: React.FormEvent) => {
    e.preventDefault();

    setIsLoading(true);
    signIn(loginEmail, loginPassword);

    setTimeout(() => {
      setIsLoading(false);
      navigate('/dashboard');
    }, 1000);
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-background via-background to-primary/5">
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center mb-8 gap-2">
          <Shield className="h-12 w-12 text-primary" />
          <h1 className="text-4xl font-bold">HawkEye</h1>
        </div>

        <Card className="border-border">
          <CardHeader>
            <CardTitle>Welcome to HawkEye</CardTitle>
            <CardDescription>Sign in to access the advanced security platform</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSignIn} className="space-y-4">
              <div className="flex items-center space-x-2 mb-4">
                <Checkbox
                  id="demo"
                  checked={useDemoCredentials}
                  onCheckedChange={handleDemoToggle}
                />
                <Label
                  htmlFor="demo"
                  className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                >
                  Use demo credentials
                </Label>
              </div>

              <div className="space-y-2">
                <Label htmlFor="login-email">Email</Label>
                <Input
                  id="login-email"
                  type="email"
                  placeholder="you@example.com"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="login-password">Password</Label>
                <Input
                  id="login-password"
                  type="password"
                  placeholder="••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  required
                />
              </div>

              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? "Signing in..." : "Sign In"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Auth;
