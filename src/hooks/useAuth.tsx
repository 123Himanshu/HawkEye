import { createContext, useContext, useState, ReactNode } from 'react';
import { useToast } from '@/hooks/use-toast';

interface MockUser {
  id: string;
  email: string;
  full_name: string;
}

interface AuthContextType {
  user: MockUser | null;
  loading: boolean;
  signIn: (email: string, password: string) => void;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<MockUser | null>({
    id: '1',
    email: 'analyst@hawkeye.com',
    full_name: 'Security Analyst'
  });
  const [loading] = useState(false);
  const { toast } = useToast();

  const signIn = (email: string, _password: string) => {
    const mockUser: MockUser = {
      id: '1',
      email: email,
      full_name: 'Security Analyst'
    };
    
    setUser(mockUser);
    toast({
      title: "Welcome back!",
      description: "You have successfully signed in.",
    });
  };

  const signOut = () => {
    setUser(null);
    toast({
      title: "Signed out",
      description: "You have been signed out successfully.",
    });
  };

  return (
    <AuthContext.Provider value={{ user, loading, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
