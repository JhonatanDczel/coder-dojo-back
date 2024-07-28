from django.shortcuts import redirect
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework import permissions, status
from django.urls import reverse
from .models import AppUser, PerfilDocente
from .serializers import *
from django.contrib.auth import authenticate, login, logout

class IsStaffUser(permissions.BasePermission):
    def has_permission(self, request, view):
        # Check if the user is authenticated and is a staff member
        return request.user and request.user.is_authenticated and request.user.is_staff
      
class IsDocente(permissions.BasePermission):
    def has_permission(self, request, view):
       return request.user.is_docente

@api_view(['POST'])
def logout_user(request):
    logout(request)
    return Response({'detail': 'Logged out successfully'}, status=status.HTTP_200_OK)

# Create your views here.
@api_view(['GET'])
@authentication_classes([SessionAuthentication])
def home(request):
  content = None
  try:
    if (request.user.is_estudiante != request.user.is_docente):
        print("Eres o bien estudiante o bien docente")
        return redirect(reverse('clase', args=[0 if request.user.is_estudiante else 1]))
  except:
    print("algo raro sucedio: home")
    content = {
        "director" : "Bienvenido, Identificate como usuario de esta app antes de ingresar a una clase"
    }
  return Response(content)

@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def clase(request, miembro=-1):
  # toca verificar que el usuario tenga su perfil de miembro
  usuario = request.user
  content = {}
  if not (miembro == 0 or miembro == 1):
    content["director"] = "Se entra por la puerta principal con tus credenciales muchachon ✋"
    return redirect('backdoor')
  if(miembro == 1):
    #es profe, deberia tener un perfil de profesor
    perfil = PerfilDocente.objects.get(user=usuario)
    if not perfil:
      return redirect('phony_teacher')
    clases = perfil.clases.all()
    return Response(ClaseSerializerAlDocente(clases, many=True).data)
  if(miembro==0):
    perfil = PerfilEstudiante.objects.get(user=usuario)
    if not perfil:
      return redirect('phony_estudiante')
    clases = perfil.clases.all()
    return Response(ClaseSerializerAlEstudiante(clases, many=True).data)

@api_view(['POST'])
@authentication_classes([SessionAuthentication])
def loginUser(request):
    print("Hola, antes de sacar datos")
    
    # Obtener datos del request
    username = request.data.get('username')
    password = request.data.get('password')
    rol = request.data.get('rol')
    
    print(f"Attempting login with username: {username}")
    print(f"Attempting login with password: {password}")
    print(f"Attempting login with rol: {rol}")
    
    # Verificar si username y password están presentes
    if not username:
        print("Username no recibido")
        return Response({'detail': 'Username no proporcionado'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not password:
        print("Password no recibido")
        return Response({'detail': 'Password no proporcionado'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not rol:
        print("Rol no recibido")
        return Response({'detail': 'Rol no proporcionado'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Autenticar al usuario
    user = authenticate(username=username, password=password)
    
    # Verificar si el usuario fue autenticado
    if user is not None:
        # Comprobar el rol del usuario
        if rol == 'Docente':
            if user.is_docente:
                login(request, user)
                print("Logeado correctamente como docente")
                return Response({'detail': 'Login successful como docente'}, status=status.HTTP_200_OK)
            else:
                print("Usuario autenticado, pero no es docente")
                return Response({'detail': 'No tiene permisos para el rol de docente'}, status=status.HTTP_403_FORBIDDEN)
        
        elif rol == 'Estudiante':
            if user.is_estudiante:
                login(request, user)
                print("Logeado correctamente como estudiante")
                return Response({'detail': 'Login successful como estudiante'}, status=status.HTTP_200_OK)
            else:
                print("Usuario autenticado, pero no es estudiante")
                return Response({'detail': 'No tiene permisos para el rol de estudiante'}, status=status.HTTP_403_FORBIDDEN)
        
        else:
            print("Rol recibido no válido")
            return Response({'detail': 'Rol no válido'}, status=status.HTTP_400_BAD_REQUEST)
    
    else:
        print("No se pudo autenticar el usuario")
        return Response({'detail': 'Credenciales inválidas'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsDocente])
def Cpublicacion(request):
    serializer = RegisterPublicacionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Create Entrega
@api_view(['POST'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def Centrega(request):
    serializer = RegisterEntregaSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Retrieve Entrega
@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def Rentrega(request, pk):
    try:
        entrega = Entrega.objects.get(pk=pk)
    except Entrega.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    serializer = RegisterEntregaSerializer(entrega)
    return Response(serializer.data)

# Retrieve Publicacion
@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def Rpublicacion(request, pk):
    try:
        publicacion = Publicacion.objects.get(pk=pk)
    except Publicacion.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    serializer = RegisterPublicacionSerializer(publicacion)
    return Response(serializer.data)

# Update Publicacion
@api_view(['PUT'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsDocente])
def Upublicacion(request, pk):
    try:
        publicacion = Publicacion.objects.get(pk=pk)
    except Publicacion.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    serializer = RegisterPublicacionSerializer(publicacion, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Update Entrega
@api_view(['PUT'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def Uentrega(request, pk):
    try:
        entrega = Entrega.objects.get(pk=pk)
    except Entrega.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    serializer = RegisterEntregaSerializer(entrega, data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete Entrega
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def Dentregar(request, pk):
  
  
  try:
      entrega = Entrega.objects.get(pk=pk)
  except Entrega.DoesNotExist:
      return Response(status=status.HTTP_404_NOT_FOUND)
  entrega.delete()
  return Response(status=status.HTTP_204_NO_CONTENT)

# Delete Publicacion
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsDocente])
def Dpublicacion(request, pk):
  try:
    publicacion = Publicacion.objects.get(pk=pk)
  except Publicacion.DoesNotExist:
    return Response(status=status.HTTP_404_NOT_FOUND)
  publicacion.delete()
  return Response(status=status.HTTP_204_NO_CONTENT)

# Create Asignacion
@api_view(['POST'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsDocente])
def Casignacion(request):
    serializer = RegisterAsignacionSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete Asignacion
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsDocente])
def Dasignacion(request, pk):
    try:
        asignacion = Asignacion.objects.get(pk=pk)
    except Asignacion.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    asignacion.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)

# Delete Clase
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication])
@permission_classes(IsStaffUser)
def Dclase(request, pk):
    try:
        clase = Clase.objects.get(pk=pk)
    except Clase.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    clase.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
@authentication_classes([SessionAuthentication])
def create_appuser(request):
    serializer = AppUserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({'detail': 'User created successfully'}, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def RperfilDocente(request, pk):
    try:
        docente = PerfilDocente.objects.get(pk=pk)
    except Entrega.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    serializer = PerfilDocenteSerializer(docente)
    return Response(serializer.data)

@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([permissions.IsAuthenticated])
def get_user_data(request):
  user = request.user
  user_data = {
    'username': user.username,
    'rol': 'Docente' if user.is_docente else 'Estudiante',
  }
  return Response(user_data)

@api_view(['GET'])
def is_authenticated(request):
    return Response({'authenticated': not request.user.is_anonymous}, status=status.HTTP_200_OK)


