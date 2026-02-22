import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

class NetworkAutoencoder(nn.Module):
    def __init__(self):
        super(NetworkAutoencoder, self).__init__()
        
        # 1. THE ENCODER: Compresses the 4 network features down to a 2-dimensional "bottleneck"
        self.encoder = nn.Sequential(
            nn.Linear(4, 3),
            nn.ReLU(),
            nn.Linear(3, 2),
            nn.ReLU()
        )
        
        # 2. THE DECODER: Attempts to expand the 2 numbers back into the original 4 features
        self.decoder = nn.Sequential(
            nn.Linear(2, 3),
            nn.ReLU(),
            nn.Linear(3, 4),
            nn.Sigmoid()  # Forces the output to be between 0 and 1 (normalized)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# ==========================================
# TRAINING PHASE (Simulated)
# ==========================================
if __name__ == "__main__":
    print("Initializing Sentinel AI Brain...")
    
    # We set a seed so the math is reproducible every time we run it
    torch.manual_seed(42)
    np.random.seed(42)

    # 1. Generate "Normal" Traffic Data (Simulating the 54-1500 byte packets you saw)
    # Features: [Protocol_TCP, Protocol_UDP, Normalized_Size, Time_Delta]
    # We generate 1000 rows of safe, boring traffic.
    normal_traffic = np.random.normal(0.2, 0.05, size=(1000, 4))
    
    # Convert NumPy arrays to PyTorch Tensors
    data_tensor = torch.tensor(normal_traffic, dtype=torch.float32)

    # 2. Initialize the AI
    model = NetworkAutoencoder()
    criterion = nn.MSELoss() # Mean Squared Error calculates the "Reconstruction Loss"
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    print("Training model on normal baseline traffic...")
    
    # 3. Train the AI to memorize "Normal"
    epochs = 30
    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        outputs = model(data_tensor)
        loss = criterion(outputs, data_tensor)
        loss.backward()
        optimizer.step()
        
        if (epoch + 1) % 10 == 0:
            print(f"Epoch [{epoch+1}/{epochs}], Training Loss: {loss.item():.6f}")

    print("\n--- Training Complete ---")

    # ==========================================
    # INFERENCE PHASE (Testing an Anomaly)
    # ==========================================
    model.eval() # Switch to evaluation mode
    
    # Let's test two packets. 
    # Packet A: Looks exactly like the normal traffic it was trained on.
    # Packet B: A massive anomaly (e.g., weird protocol, massive size spike).
    test_normal = torch.tensor([[0.21, 0.19, 0.20, 0.22]], dtype=torch.float32)
    test_anomaly = torch.tensor([[0.99, 0.01, 0.95, 0.88]], dtype=torch.float32)

    with torch.no_grad():
        # Test Normal
        recon_normal = model(test_normal)
        loss_normal = criterion(recon_normal, test_normal).item()
        
        # Test Anomaly
        recon_anomaly = model(test_anomaly)
        loss_anomaly = criterion(recon_anomaly, test_anomaly).item()

    print(f"\n[Test A] Safe Packet Loss Score:    {loss_normal:.6f}")
    print(f"[Test B] Anomaly Packet Loss Score: {loss_anomaly:.6f}")
    
    if loss_anomaly > (loss_normal * 5):
        print("\n🚨 SYSTEM ALERT: Anomaly effectively isolated from normal baseline! 🚨")